[org 0x0]
[bits 64]
entry:
    mov r13, 0x100000
    xor r12, r12

loop2:
    lea rsi, [rel output]
    mov rax, 1
    int 0x0
    cmp r13, r12
    jl good_exit
    inc r12
    jmp loop2

fail:
    mov rax, 0x1
    lea rsi, [rel bad]
    int 0x0
    jmp bad_exit

good_exit:
    mov rax, 0x1
    lea rsi, [rel done]
    int 0x0
bad_exit:
    xor rax, rax
    int 0x0

output:
    db "CHEF", 0xa, 0

bad:
    db "bad",0x0a, 0

done:
    db "done", 0x0a, 0
