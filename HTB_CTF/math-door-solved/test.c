
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>


int main(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stderr,NULL,_IONBF,0);
    
    void* chef = malloc(0x428);
    void* chef2 = malloc(0x18);
    void* chef3 = malloc(0x428);
    free(chef);
    free(chef);
    exit(0);
}
