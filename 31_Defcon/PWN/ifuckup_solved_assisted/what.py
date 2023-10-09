ULL = 2**32 - 1


class Well512a:
    def __init__(self, state, ind=0):
        assert len(state) == 16
        self.state = [ind] + state

    def get_rand_val(self, domul=False):
        esi = self.state[0]  # 32 bits
        ebx_1 = (esi + 0xf) & 0xf  # 4 bits
        ecx = self.state[((esi + 0xd) & 0xf) + 1]  # 32 bits
        edi = self.state[ebx_1 + 1]  # 32 bits
        edx_6 = (self.state[esi + 1] << 0x10 ^ self.state[esi + 1] ^ ecx ^ ecx << 0xf) & ULL  # 32 bits
        ecx_2 = self.state[((esi + 9) & 0xf) + 1]  # 32 btis
        edx_11 = ecx_2 >> 0xb ^ ecx_2  # 32 bits
        ecx_4 = edx_6 ^ edx_11  # 32 bits
        self.state[esi + 1] = ecx_4  # 32 bits
        edi_5 = (edx_6 << 0x12 ^ edi << 2 ^ edi ^ edx_11 ^ edx_11 << 0x1c ^ (ecx_4 << 5 & 0xda442d24)) & ULL  # 32 bits
        self.state[ebx_1 + 1] = edi_5  # 32 bits
        self.state[0] = ebx_1  # 4 bits
        if domul:
            return max(edi_5 - 1, 0)
            #return edi_5
        return edi_5 / 2**32

ind1 = 0x3
state1 = [0xcee26c12,0x0a2bc9c6,0x2c41eb84,0x024cb140,0x84003a53,0x6e94787d,0x69008e3d,0xa2a0e6e0,0x58edd419,0x7e4b56ee,0xc9a8df90,0x5cf60bca,0x2994a92a,0x3f53f2f2,0x9f33218b,0x437ba38b]

ind2 = 0xa
state2 = [0x29d885ed,0x25df30bb,0xc53a0933,0x2088988d,0x4e39e503,0x39bf0227,0x9cf6b933,0xd712a65f,0x1da92553,0x2a046f7e,0xa82bf139,0xbda9cd6a,0x23ca18c3,0x01b14610,0x98af7787,0x1ea3c174]

rng1 = Well512a(state1, ind1)
rng2 = Well512a(state2, ind2)

print("Random Values:")

v0 = 0

while v0 != 65:
    v0+= 1
    out = rng1.get_rand_val(domul=True)
    print(hex(out)[2:])

    if v0&7 != 0:
        if v0&3==0:
            print("-")
            for i in range(int(rng2.get_rand_val()*255)):
                rng1.get_rand_val()

    else:
        print()
