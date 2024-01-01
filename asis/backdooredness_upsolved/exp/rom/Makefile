all:
	cc65 -O -t c64 pwn.c
	ca65 -t c64 pwn.s
	ca65 -t c64 pwn_asm.s
	cl65 -o ../pwn.nes -t nes pwn.o pwn_asm.o
