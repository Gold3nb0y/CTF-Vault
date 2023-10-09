[org 0x0]
[bits 64]

get_program_info:
    mov rax, 3 ; ddGet data
    std
    lea rdi, [rel buffer]
    mov rcx, 0x33 ; Program data JSON size
    mov rdx, 0 ; Program data JSON is at offset 0
    int 0x0

    cld
    mov rax, 1
    mov rcx, 0x33
    mov rsi, 0x4a
    int 0x0
    add rsi, 1

    mov rax, 0
    int 0x0

    

buffer2:
    times 64 db 0

buffer:
    times 64 db 0
