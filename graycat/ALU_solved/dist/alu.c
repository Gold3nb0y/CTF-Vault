#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#define SZ 32

typedef struct {
    bool is_reg;
    int v;
} opd_b;

opd_b vm_read_opd_b(char* buf) {
    opd_b b;
    if ((('0' <= buf[0]) && (buf[0] <= '9')) || buf[0] == '-') { //if it is a dec number
        b.is_reg = false;
        b.v = atoi(buf);
    } else { //otherwise
        b.is_reg = true;
        b.v = *(u_char*)buf - 'a';
    }
    printf("%d, %d\n", b.is_reg, b.v);
    return b;
}

//I belive this is a way of storing instructions?

bool vm_run() {
    int regs['z' - 'a' + 1]; //registers
    char line[SZ];

    memset(regs, 0, sizeof regs);

    while (true) {
        printf("> ");
        fgets(line, SZ, stdin);
        if (line[0] == '\n') break;

        int a = *(u_char*)(line + 4) - 'a'; //reads in the char at position 5 in the string, this could be the address I'm working with?
        opd_b bv = vm_read_opd_b(line + 6);
        int b = bv.is_reg ? regs[bv.v] : bv.v; //if is is a register, get the value stored in it and store it in b. if not b is just the value

        if (strncmp(line, "inp", 3) == 0) {
            printf("inp %c > ", a + 'a');
            scanf("%d%*c", &regs[a]);
        } else if (strncmp(line, "add", 3) == 0) {
            regs[a] += b;
        } else if (strncmp(line, "mul", 3) == 0) {
            regs[a] *= b;
        } else if (strncmp(line, "div", 3) == 0) {
            regs[a] /= b;
        } else if (strncmp(line, "mod", 3) == 0) {
            regs[a] %= b;
        } else if (strncmp(line, "eql", 3) == 0) {
            regs[a] = regs[a] == b;
        }
        else break;
    }
    return regs['z' - 'a'] == 0; // no more instrs, eval 'z == 0'
}

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main() {
    setup();

    char instrs[SZ];

    puts("--- Day 24: Arithmetic Logic Unit ---");
    puts("input MONAD: ");

    bool success = vm_run();

    printf("MONAD says your model number is %s\n", success ? "valid" : "invalid");
}


/* NOTES
ALU refers to the instructions preformed on registers. in this challenge they give you 26 registers to work with, a-z. 
is_reg refers to wether or not the instruction is a register. These values are stored but never displayed

idea's:
    manipulate array to be filled with shellcode, then somehow redirect code execution to it. probably not the solution as nx stack is enabled
    libc's and ld's are given, maybe there is a way to overwrite the GOT? I have a couple of invalid entries, 0-9 and special chars. These allow me to write
        outside of the stack bounds. there are a couple of one_gadgets in libc that I could potentially call if I could somehow leak the libc offset.
        This would involve overwriting the return addr with something, reading an address, and then restarting the program so I can utalize the address. 
        PIE makes this hard, probably impossible. If I can manage a leak though this would come in clutch
    divide by 0? probably not, just causes a floating point exception
    printf@plt stored right at the start of the stack don't know why

    I can manipulate registers out of bounds, I can also add previous registers into those bounds, using this I don't have to leak the addresses
    modding a register by 1 always gives 0, at least from what I can tell right now, so it is a good way to move things out before I need to use them
    one gadgets should be clutch here. I think I can clear the r12 and r15 registers with a gadget, and then call the one gadget  


*/