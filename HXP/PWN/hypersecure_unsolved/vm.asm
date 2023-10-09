bits 64

section .text

global _start

_start:

    mov rcx, 8
    mov rdi, 0x2000
    mov ax, 0x41
    rep stosb
    ;mov rdi, 0x1000
    ;mov ax, 0x42
    ;mov rcx, 8
    ;rep stosb

    ;mov rdi, 0
    ;mov ax, 0x43
    ;mov rcx, 0x43
    ;rep stosb
    ;
    mov rax, 0x0000000005597000
    mov cr4, rax
    mov cr3, rax
    ;mov rcx, 0x1000
    ;mov ax, 0x43
    ;rep stosb
    
    ;dec rcx
    ;pop r15
    ;cmp r15, 0
    ;jne _exit
    ;cmp rcx, 0
    ;je _exit
    ;jmp loop

    ;mov rax, 0x0000000005597000

    ;mov cr3, rax
    jmp _exit

_exit:
    vmmcall
