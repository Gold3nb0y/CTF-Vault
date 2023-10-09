[org 0x0]
[bits 64]
entry:
    mov r12, 0x2000
    xor r13, r13
    xor rax, rax
    
loop: ;igev da debugger some time to attach
    inc r13
    mov byte [rel output + r13], 0x41
    cmp r13, r12
    jl loop
    ;mov rl, byte [rel buffer+r13]
    
    mov rdi, 0x69
    lea rsi, [rel output]
    xor rax, rax
    add rax, 1
    int 0x0
    jmp exit
;end:
;    jmp entry
fail:
    lea rsi, [rel bad]
    xor rax, rax
    inc rax
    int 0x0
    jmp exit

exit:
    xor rax, rax
    int 0x0

output:
    db "A", 0

bad:
    db "bad", 0

buffer:
    ;db 0x48, 0x8d, 0x35, 0x0e, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xcd, 0, 0xb8, 0, 0, 0, 0, 0xcd, 0, 0x43, 0x48, 0x46, 0x45, 0
