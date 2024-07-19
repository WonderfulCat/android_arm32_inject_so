#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>

#define LIBC_PATH "/system/lib/libc.so"
#define LINKER_PATH "/system/bin/linker"
#define INJECT_SO_PATH "/data/user/libhello.so"
#define DLL_PUBLIC  __attribute__ ((visibility("default")))


pid_t get_pid(const char* process_name);
void* get_module_base_addr(pid_t pid, const char* moduleName);
void* get_remote_func_addr(pid_t pid, const char* module_name, void* local_func_addr);
void* get_remote_mmaped_string_addr(pid_t pid, struct pt_regs* regs, const char* content);

int call_remote_mmap(pid_t pid, struct pt_regs* regs);
void* call_remote_dlopen(pid_t pid, struct pt_regs* regs, void* remote_mmap_addr);
void* call_remote_dlsym(pid_t pid, struct pt_regs* regs, void* remote_handle, void* remote_mmap_addr);

int ptrace_attach(pid_t pid);
int ptrace_detach(pid_t pid);
int ptrace_continue(pid_t pid);
int ptrace_getregs(pid_t pid, struct pt_regs* regs);
int ptrace_setregs(pid_t pid, struct pt_regs* regs);
int ptrace_read_data(pid_t pid, void* read_addr, void* read_buf, size_t size);
int ptrace_write_data(pid_t pid, void* write_addr, void* write_data, size_t size);
int ptrace_call(pid_t pid, void* func_addr, long* parameters, int num_params, struct pt_regs* regs);


int inject_so_file(pid_t pid, const char* so_path, const char* entry_func_name, const char* entry_func_data);

 

int main() {
    pid_t pid = get_pid("./hello");
    printf("find pid %d\n", pid);

    inject_so_file(pid, INJECT_SO_PATH , "Test" ,NULL);
    return 0;
}

 

int inject_so_file(pid_t pid, const char* so_path, const char* entry_func_name, const char* entry_func_data) {
    if (ptrace_attach(pid) != 0) {
        return -1;
    }

    struct pt_regs cur_regs;
    struct pt_regs ori_regs;

    if (ptrace_getregs(pid, &cur_regs) != 0) {
        return -1;
    }

    //保存寄存器
    memcpy(&ori_regs, &cur_regs, sizeof(cur_regs));

    printf("cur_cpsr = %lx,  ori_cpsr = %lx\n", cur_regs.ARM_cpsr, ori_regs.ARM_cpsr);

    void* so_addr = NULL;

    //获取分配至内存的字符串地址
    void* remote_dlopen_arg0_addr = get_remote_mmaped_string_addr(pid, &cur_regs, so_path);

    void* remote_dlopen_ret_addr = call_remote_dlopen(pid, &cur_regs, remote_dlopen_arg0_addr);
    if (!remote_dlopen_ret_addr) {
        printf("Call dlopen Failed , path : %s \n", so_path);
        return -1;
    }

    if (entry_func_name) {
        void* remote_dlsym_arg1_addr = get_remote_mmaped_string_addr(pid, &cur_regs, entry_func_name);;
        void* remote_symble_addr = call_remote_dlsym(pid, &cur_regs, remote_dlopen_ret_addr, remote_dlsym_arg1_addr);
        if (remote_symble_addr) {
            void* remote_func_arg_addr = NULL;
            if (entry_func_data) {
                remote_func_arg_addr = get_remote_mmaped_string_addr(pid, &cur_regs, entry_func_data);
            }
            long parameters[1];
            parameters[0] = (long)remote_func_arg_addr;

            printf("entry point : %p\n", remote_symble_addr);
            ptrace_call(pid, remote_symble_addr, parameters, 1, &cur_regs);
        }
        else {
            printf("Cannot found address of symbol: [%s] !!!\n", entry_func_name);
        }
      }


    if (ptrace_setregs(pid, &ori_regs) < 0) {
        printf("Could not recover regs.\n");
        return -1;
    }

    ptrace_detach(pid);
    return 0;
}

// remote_mmap_addr mmap 分配的地址,包含了so文件路径
void* call_remote_dlopen(pid_t pid, struct pt_regs* regs, void* remote_mmap_addr) {
    long parameters[2];
    parameters[0] = (long)remote_mmap_addr;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;

    //void *dlopen(const char *filename, int flag);
    void* dlopen_addr = get_remote_func_addr(pid, LINKER_PATH, (void*)dlopen);
    void* dlerror_addr = get_remote_func_addr(pid, LINKER_PATH, (void*)dlerror);

    //printf("dlopen addr : %p\n", dlopen_addr);

    if (ptrace_call(pid, dlopen_addr, parameters, 2, regs) < 0){
        printf("Call dlopen Failed\n");
        return NULL;
    }

    void* remote_module_addr = (void*)regs->ARM_r0;
    printf("ptrace_call dlopen success, Remote module Address: 0x%lx\n", (long)remote_module_addr);

    if ((long)remote_module_addr == 0x0) {
        printf("dlopen error.\n");

        if (ptrace_call(pid, dlerror_addr, parameters, 0, regs) < 0) {
            printf("Call dllerror failed.\n");
            return NULL;
        }

        void* error_addr = (void*)regs->ARM_r0;
        char local_eror_info[1024] = { 0 };
        ptrace_read_data(pid, error_addr, local_eror_info, sizeof(local_eror_info));
        printf("dlopen error : %s\n", local_eror_info);
        return NULL;
    }

    return remote_module_addr;
}

//remote_mmap_addr分配的地址,包含了dlsym字符串参数
void* call_remote_dlsym(pid_t pid, struct pt_regs* regs, void* remote_handle, void* remote_mmap_addr) {
    long parameters[2];
    parameters[0] = (long)remote_handle;
    parameters[1] = (long)remote_mmap_addr;

    void* dlsym_addr = get_remote_func_addr(pid, LINKER_PATH, (void*)dlsym);
    //printf("dlsym addr : %p\n", dlsym_addr);

    if (ptrace_call(pid, dlsym_addr, parameters, 2, regs) < 0) {
        printf("Call dlsym Failed.\n");
        return NULL;
    }

    void* remote_module_addr = (void*) regs->ARM_r0;
    printf("ptrace_call dlsym success, Remote module Address: 0x%lx\n", (long)remote_module_addr);

    if ((long)remote_module_addr == 0x0) {
        printf("dlsym error.\n");
        return NULL;
    }

    return remote_module_addr;
}

//创建空间
int call_remote_mmap(pid_t pid, struct pt_regs* regs) {
    long parameters[6];
    
    void* mmap_addr = get_remote_func_addr(pid,LIBC_PATH,(void*)mmap);
    //printf("Mmap Function Address: 0x%lx\n", (long)mmap_addr);


    //void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize);
    parameters[0] = 0; //Not needed
    parameters[1] = 0x1000;
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE;
    parameters[4] = 0; //Not needed
    parameters[5] = 0; //Not needed

    return ptrace_call(pid,mmap_addr,parameters,6,regs);
}

//写入数据到创建空间
void* get_remote_mmaped_string_addr(pid_t pid, struct pt_regs* regs, const char* content) {
    //调用mmap 分配空间
    if (call_remote_mmap(pid, regs) < 0) {
        return NULL;
    }

    //返回mmap创建的内存地址
    void* remote_mmaped_memory_addr = (void*)regs->ARM_r0;
    printf("Remote Process Map Address: 0x%lx\n", (long)remote_mmaped_memory_addr);

    //将字符串写入
    if (ptrace_write_data(pid, remote_mmaped_memory_addr, (void*)content, strlen(content) + 1) < 0) {
        printf("writing %s to process failed\n", content);
        return NULL;
    }

    return remote_mmaped_memory_addr;
}

/***********************ptrace******************/

int ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        printf("ptrace attach error , pid: %d, error: %s\n", pid, strerror(errno));
        return -1;
     }
    return 0;
}

int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        printf("ptraceDetach error, pid: %d, err: %s\n", pid, strerror(errno));
        return -1;
    }
    printf("ptraceDetach success\n");
    return 0;
}

int ptrace_call(pid_t pid, void* func_addr, long* parameters, int num_params, struct pt_regs* regs) {
    //设置寄存器参数(32位4个参数能过寄存器传递,64位8个)
    int i = 0;
    for (; i < num_params && i < 4; i++) {
        regs->uregs[i] = parameters[i];
        //printf("p : %d  = %ld\n", i, parameters[i]);
    }

    //存在多余参数,需要压栈. 32位4字节栈对齐
    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long);
        if (ptrace_write_data(pid, (void*)(regs->ARM_sp), (void*)&parameters[i], (num_params - i) * sizeof(long)) < 0) {
			return -1;
        }
    }

    regs->ARM_pc = (long) func_addr;

    // 判断跳转的地址位[0]是否为1，如果为1，则将CPST寄存器的标志T置位，解释为Thumb代码
    if (regs->ARM_pc & 1) {
        regs->ARM_pc &= (~1u); //去掉thumb最后位
        regs->ARM_cpsr |= 0x20; //设置T位(thumb标识) cpsr 第5位
        //printf("thumb!!!!! -> %lx\n", regs->ARM_cpsr);
    }
    else {
        regs->ARM_cpsr &= (~0x20); //清除T位
        //printf("ARM!!!!! -> %lx\n", regs->ARM_cpsr);
    }

    //printf("ARM_CPSR -> %lx\n", regs->ARM_cpsr);

    //设置LR = 0 函数返回时会触发异常, 再次获取程序控制权
    regs->ARM_lr = 0;

    /*
    * 对于ptrace_continue运行的进程，他会在三种情况下进入暂停状态：1.下一次系统调用 2.子进程出现异常 3.子进程退出
    * 将存放返回地址的lr寄存器设置为0，执行返回的时候就会发生错误，从子进程暂停
    */
    if (ptrace_setregs(pid, regs) < 0 || ptrace_continue(pid) < 0) {
        return -1;
    }
    
    int stat = 0;
    //参数WUNTRACED表示当进程进入暂停状态后，立即返回
    waitpid(pid, &stat, WUNTRACED);

    //0xb7f表示子进程进入暂停状态
    while ((stat & 0xFF) != 0x7f) {
        if (ptrace_continue(pid) == -1) {
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    // 获取远程进程的寄存器值，以便读取返回值R0
    if (ptrace_getregs(pid, regs) < 0) {
        return -1;
    }

    //printf("regs->ARM_r0 : %lx\n", regs->ARM_r0);
    return 0;
    
}

int ptrace_continue(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        printf("ptraceContinue error, pid: %d, error: %s\n", pid, strerror(errno));
        return -1;
    }

    printf("ptraceContinue success\n");
    return 0;
}

int ptrace_read_data(pid_t pid, void* read_addr, void* read_buf, size_t size) {
    int read_count = size / sizeof(long);
    int remain_count = size / sizeof(long);

    long peek_data = 0;
    for (int i = 0; i < read_count; i++) {
        peek_data = ptrace(PTRACE_PEEKTEXT, pid, read_addr, NULL);
        memcpy(read_buf, (void*)(&peek_data), sizeof(long));

        read_addr += sizeof(long);
        read_buf += sizeof(long);
    }

    if (remain_count > 0) {
        peek_data = ptrace(PTRACE_PEEKTEXT, pid, read_addr, NULL);
        memcpy(read_buf, (void*)(&peek_data), remain_count);
    }

    return 0;
}


int ptrace_write_data(pid_t pid, void* write_addr, void* write_data, size_t size) {
    int write_count = size / sizeof(long);
    int remain_count = size % sizeof(long);

    long poke_data = 0;
    for (int i = 0; i < write_count; i++) {
        memcpy((void *)(&poke_data), write_data, sizeof(long));

        //printf("write_data = %p, poke_data = %ld\n", write_addr, poke_data);

        if (ptrace(PTRACE_POKETEXT, pid, write_addr, poke_data) < 0) {
            printf("Write Remote Memory error, MemoryAddr: 0x%lx, error:%s\n", (long)write_data, strerror(errno));
            return -1;
        }

        write_data += sizeof(long);
        write_addr += sizeof(long);
    }

    /*
    * 读取的时候,如果不足 4 字节, 我们可以将数据直接读取出来, 不影响程序运行 
    * 写出的时候,如果写出数据不足 4 字节, 原来进程中剩余位是什么数据, 写出去时也必须是同样的数据, 否则进程运行出错 
    */ 
    long peek_data = 0;
    if (remain_count > 0) {
        //一次性必须写入 4 字节 , 如果不足 4 字节 , 先把数据读取出来 , 即读取 4 字节出来 
        peek_data = ptrace(PTRACE_PEEKTEXT, pid, write_addr, NULL);
        //假如数据有 3 字节 , 那么就将上述读取的 4 字节的前 3 个字节设置成我们要修改的数据 
        //这就保证了第 4 个字节不会出错 
        memcpy((void*)(&peek_data), write_data, remain_count);
        if (ptrace(PTRACE_POKETEXT, pid, write_addr, peek_data) < 0) {
            printf("Write Remote Memory error, MemoryAddr: 0x%lx, err:%s\n", (long)write_data, strerror(errno));
            return -1;
        }
    }  
    
    return 0;
}


int ptrace_getregs(pid_t pid, struct pt_regs*  regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        printf("ptrace getregs error , pid: %d, error: %s\n", pid, strerror(errno));
        return -1;
    }
    
    return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs* regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        printf("ptrace setregs error , pid: %d, error: %s\n", pid, strerror(errno));
        return -1;
    }
    return 0;
}



/***********************address******************/
 
void* get_remote_func_addr(pid_t pid, const char* module_name, void* local_func_addr) {
    // remote_func_addr = localFuncAddr - local_module_addr  + remote_func_addr;
    //printf("--------------------------------\n");
    void* local_module_addr = get_module_base_addr(getpid(), module_name);
    //printf("local_module_addr = %p\n", local_module_addr);
    void* remote_module_addr = get_module_base_addr(pid, module_name);
    //printf("remote_module_addr = %p\n", remote_module_addr);
    void* remote_func_addr = (void*)((long)local_func_addr - (long)local_module_addr  + (long)remote_module_addr);
    //printf("local_func_addr = %p\n", local_func_addr);
    //printf("remote_func_addr = %p\n", remote_func_addr);
    return remote_func_addr;
}

void* get_module_base_addr(pid_t pid, const char* module_name) {
    long module_base_addr = 0;
    char maps_path[128] = { 0 };
    char sz_map_file_line[1024] = { 0 };

    //get path
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* fp = fopen(maps_path, "r");

    if (fp != NULL) {
        while (fgets(sz_map_file_line, sizeof(sz_map_file_line), fp)) {
            if (strstr(sz_map_file_line, module_name)) {
                //printf("file line : %s\n", sz_map_file_line);

                char* address = strtok(sz_map_file_line, "-");
                module_base_addr = strtoul(address, NULL, 16);
                break;
            }
        }
        fclose(fp);
    }

    return (void*)module_base_addr;
}

pid_t get_pid(const char* process_name) {
    if (process_name == NULL) {
        return -1;
    }
    DIR* dir = opendir("/proc");
    if (dir == NULL) {
        return -1;
    }
    struct dirent* entry;
    int char_len = 128;

    //get pids
    while ((entry = readdir(dir)) != NULL) {
        size_t pid = atoi(entry->d_name);
        if (pid != 0) {
            char file_name[char_len];
            snprintf(file_name, char_len, "/proc/%zu/cmdline", pid);
            FILE* fp = fopen(file_name, "r");
            char temp_name[char_len];
            if (fp != NULL) {
                fgets(temp_name, char_len, fp);
                fclose(fp);
 /*               printf("file_name = %s\n", temp_name);*/
                if (strcmp(process_name, temp_name) == 0) {
                    return pid;
                }
            }
        }
    }
    return -1;
}
