#!/usr/bin/env python3

from pwn import *
import time
import sys

exe = ELF("shifty_mem_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("pwn-shifty-mem-b759fc573f32d9aa.2023.ductf.dev", 443, ssl=True)

    return r

r = conn()

sla = lambda a,b : r.sendlineafter(a,b)
sl = lambda a : r.sendline(a)
ru = lambda a : r.recvuntil(a)

sfla = lambda a,b : r.sendlineafter(f'{a}'.encode('utf-8'),f'{b}'.encode('utf-8'))
sfl = lambda a : r.sendline(f'{a}'.encode('utf-8'))
ru = lambda a : r.recvuntil(f'{a}'.encode('utf-8'))

def assemble():
    payload = "echo -ne '"
    with open("test", "rb") as payload_file:
        while (byte := payload_file.read(1)):
            payload += f'\\x{ord(byte):02x}'
    payload += f"' > /tmp/{sys.argv[1]}"
    log.info(payload)
    return payload

def main():
    payload = assemble()
    time.sleep(1)
    sl(payload)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
