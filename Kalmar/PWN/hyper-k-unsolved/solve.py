#!/usr/bin/python2

from pwn import *
import sys
import base64

exe = ELF("system/main")

g = lambda r: gdb.attach(r)
ru = lambda r,a: r.recvuntil('{}'.format(a))
sla = lambda r,a,b: r.sendlineafter('{}'.format(a),'{}'.format(b))


def conn():
    if args.LOCAL:
        #r = remote("localhost", 9001)
        r = process("stdbuf -i0 -o0 -e0 ./run.sh".split())
    else:
        r = remote("130.61.225.80", 1337)

    return r

"""
1) create
2) mmap
3) munmap
4) read
5) write
6) get registers
7) set registers
8) delete
9) run
10) wait
"""
def create(r, idx):
    sla(r,':',1)
    sla(r,':', idx)
    return

def mmap(r):
    sla(r,':',2)
    return

def munmap(r):
    sla(r,':',3)
    return

def read(r):
    sla(r,':',4)
    return

def write(r):
    sla(r,':',5)
    return

def get_reg(r):
    sla(r,':',6)
    return

def set_reg(r):
    sla(r,':',7)
    return

def delete(r):
    sla(r,':',8)
    return

def run(r):
    sla(r,':',9)
    return

def wait(r):
    sla(r,':',10)
    return

def main():
    r = conn()

    create(r, 0)

    chef = ru(r, ":")
    log.info("BLAH: {}".format(chef))
#    create(r, 0) 

    r.interactive()

if __name__ == '__main__':
    main()
