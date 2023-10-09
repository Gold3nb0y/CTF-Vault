#!/usr/bin/env python3

import sys

sum = 0
max = 0
for c in sys.argv[1]:
    if max >= 7:
        break
    sum += ord(c)
    max += 1

sum += 0x0a
sum = sum & 0x3f
print(hex(sum))

