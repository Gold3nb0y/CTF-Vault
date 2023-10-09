#!/usr/bin/env python3

from pwn import *

exe = ELF("dicer-visor_patched")
libc = ELF("libc6_2.34-0ubuntu1_amd64.so")

context.binary = exe


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
