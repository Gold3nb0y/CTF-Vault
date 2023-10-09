#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/msg.h>
#include <string.h>
#include <sys/timerfd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#define IOCTL_SIZE 0x10
#define MSG_SIZE 128 -48
#define MSG_SPRAY_SIZE 0x10

int k32_fd;

typedef struct msg_msg_msg {
    long mtype;
    char mtext[MSG_SIZE];
} msg_msg_msg;


//long chad_alloc(char *data){
//    struct request req;
//    req.idx = 1;
//    memcpy(req.buffer, data, CHUNK_SIZE);
//    return ioctl(sofire_fd, 0xdeadbeef, &req);
//}



//int create_timer(int leak)
//{
//    struct itimerspec its;
//
//    its.it_interval.tv_sec = 0;
//    its.it_interval.tv_nsec = 0;
//    its.it_value.tv_sec = 10;
//    its.it_value.tv_nsec = 0;
//
//    int tfd = timerfd_create(CLOCK_REALTIME, 0);
//    timerfd_settime(tfd, 0, &its, 0);
//
//    if (leak)
//    {
//        close(tfd);
//        sleep(1);
//        return 0;
//    }
//}
typedef struct params{
    char data[24];
    int size;
}params;

int main(int argc, char *argv[]){
    unsigned long ret;
    unsigned long long leaks;
	int k32_fd = open("/dev/k32", O_RDONLY);

    struct params r1 = {
        "CHEFCHEFCHEF", 10
    };
    ioctl(k32_fd, 0xb10550a,&r1); 
}
