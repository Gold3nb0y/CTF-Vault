#!/usr/bin/python2

from pwn import *

exe = ELF("coopy_patched")
libc = ELF("libc-2.31.so")
ld = ELF("ld-2.31.so")

context.binary = exe



def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("addr", 1337)

    return r

r = conn()

def add(string):
    r.sendline('1')
    r.recvuntil('enter string:')
    #print string
    r.sendline('{}'.format(string))
    r.recvuntil('>')

def leet(index):
    r.sendline('1337')
    r.recv()
    r.sendline('{}'.format(index))
    return r.recvuntil('>')

def main():
    r.recv()
    # good luck pwning :)
    letters = ['A','B','C','D','E']
    for l in letters:
        add(l*4)

    chef = leet(0)
    print chef
    gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
