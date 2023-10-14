#!/usr/bin/env python

from Crypto.PublicKey import RSA

key = RSA.generate(2048)
print(hex(key.n))
print(hex(key.e))
print(hex(key.d))
