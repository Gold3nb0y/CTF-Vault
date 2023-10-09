with open('./samples/0b7ea2bb6725cf6158f39894e3d8fc0c.elf', 'rb') as f:
    f.seek(0x348)
    code = f.read(0xFF)
    f.seek(0xA80)
    key = f.read(0x20)

# cipher = ARC4.new(key)
# pt = cipher.decrypt(code)
# print(pt.hex())


def rc4_crypto(buffer):
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


pt = rc4_crypto(code)
print(pt.hex())
