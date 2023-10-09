from pwn import *


context.arch = 'amd64'

def rc4_crypto(buffer, key):
    box = list(range(256))
    outbuf = bytearray(buffer)
    j = 0
    for i in range(256):
        box[i] = i

    for _i in range(256):
        tmp = box[_i]
        j = (key[_i & 31] + tmp + j) & 0xFF
        box[_i] = box[j]
        box[j] = tmp

    __i = 0
    a = 0
    while __i != 255:
        a = (a + 1) & 0xFF
        _tmp = box[a]
        j = (_tmp + j) & 0xFF
        box[a] = box[j]
        box[j] = _tmp
        outbuf[__i] ^= box[(box[a] + _tmp) & 0xFF]
        __i += 1
    return bytes(outbuf)



with open('./samples/65a52fae99ee9a03f964d74f4287e7bd.elf', 'rb') as f:
    raw_data = f.read()
    data = raw_data[0x348:0x348+0x100]
    ind = raw_data.index(b"\x02\x86")
    off = u32(raw_data[ind+2:ind+6]) - 0x200000
    key = raw_data[off:off+0x20]

plain = rc4_crypto(data, key)

ans = b""
plain = plain[0x10:]
for i in range(0x20):
    ans += bytes([plain[0]])
    if i == 0x1f:
        break
    plain = plain[plain.index(b"\x80x")+3:]
ans = ans.decode()
print(ans)
