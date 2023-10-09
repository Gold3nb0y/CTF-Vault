#!/usr/bin/python2

from pwn import *

exe = ELF("last_minute_pwn_patched")

context.binary = exe

sla = lambda r, a, b: r.sendlineafter('{}'.format(a), '{}'.format(b))


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

def sl(r, payload):
    sla(r, '>>', payload)

def solve(r):
    sl(r, 1)
    chef = r.recvline()
    chefs = chef.split(" ")
    a = chefs[3]
    b = chefs[5]
    sum = int(a) + int(b)
    log.info('{}'.format(sum))
    r.sendline('{}'.format(sum))

def main():
    r = conn()

    sl(r, 1)
    sl(r, 'y')
    for i in range(31):
        solve(r)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
