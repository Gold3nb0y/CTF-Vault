#!/usr/bin/env python3

from pwn import *

exe = ELF("chal_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe
sla = lambda r,a,b : r.sendlineafter(a,"{}".format(b))
op = lambda r,idx : r.sendlineafter("Set Value\n", "{}".format(idx))
ru = lambda r,a    : r.recvuntil(a)
ra = lambda r,a    : r.recv(a)
sl = lambda r,a    : r.sendline("{}".format(a))
rl = lambda r      : r.recvline()

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
