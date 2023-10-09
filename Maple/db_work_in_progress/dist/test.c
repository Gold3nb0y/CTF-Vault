#include <stdlib.h>
#include <stdio.h>

int main(void){
    void *p1, *p2, *p3, *p4;
    p1 = malloc(0x20);
    p2 = malloc(0x20);
    p3 = malloc(0x20);
    p4 = malloc(0x20);

    free(p1);
    free(p2);
    free(p3);
    free(p1);

    return 0;
}
