#!/usr/bin/env python3
from pwn import *

r = connect("bank.hsctf.com", 1337)

for i in range(5):
    n = int(r.recvline())
    print(n)
    res = 0
    offsets = []
    for x in range(n):
        a = r.recvline().split()
        if (int(a[1]) - int(a[0])) <= 20:
            offsets.append((int(a[0]),int(a[1])))
    
    offsets.sort()
    print(offsets)
    cur = offsets[0][0] + 10
    current_offset = 1
    max = len(offsets)
    res = 1
    while cur < offsets[-1][1] and current_offset < max:
        print(cur)
        working  = offsets[current_offset]
        if cur < working[0]:
            log.info(f"include {offsets[current_offset]}")
            cur = working[0] + 10
            res += 1
        elif cur < working[1] and working[1] - cur >= 10:
            log.info(f"include 2 {offsets[current_offset]}")
            cur = cur + 10
            res += 1
        current_offset += 1
    print(res)
    #bres = bytes(str(current_offset), 'utf-8')
    r.sendline(f"{res}")
#print(r.recv())
r.interactive()
