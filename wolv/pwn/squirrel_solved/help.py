#!/usr/bin/python3

import sys

sum = 0
for char in sys.argv[1]:
    print(char)
    sum += ord(char) *31

print(f"hash: {sum}")
print(f"index: {sum%10}")
