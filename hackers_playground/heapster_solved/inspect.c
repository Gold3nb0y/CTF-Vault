#include <stdio.h>
#include <stdlib.h>

int main(void){
    void* ptr = malloc(0x420);
    free(ptr);
    return 0;
}
