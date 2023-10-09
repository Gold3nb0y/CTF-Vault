from prngs import *
import random
from z3 import *


class sage_sym_prng:
    def __init__(self,state):
        assert len(state) == 16
        self.state = [0] + state

    def clock(self):
        prev = self.state[0]  # 32 bits
        pprev = (prev + 0xf) & 0xf  # 4 bits
        c1 = self.state[((prev + 0xd) & 0xf) + 1]  # 32 bits
        c2 = self.state[pprev + 1]  # 32 bits

        temp1 = vector(list(self.state[prev + 1][0x10:]) + [0 for _ in range(0x10)])
        temp2 = vector(list(c1[0xf:]) + [0 for _ in range(0xf)])

        t0 = temp1 + self.state[prev + 1] + c1 + temp2  # 32 bits
        c3 = self.state[((prev + 9) & 0xf) + 1]  # 32 btis

        temp3 = vector([0 for _ in range(0xb)] + list(c3[:-0xb]))
        c4 = temp3 + c3  # 32 bits
        c5 = t0 + c4  # 32 bits
        self.state[prev + 1] = c5  # 32 bits

        new1 = vector(list(t0[0x12:]) + [0 for _ in range(0x12)])
        new2 = vector(list(c2[0x2:]) + [0 for _ in range(0x2)])
        new3 = vector(list(c4[0x1c:]) + [0 for _ in range(0x1c)])
        new4 = vector(list(c5[0x5:]) + [0 for _ in range(0x5)])
        new5 = []

        for x, y in zip(new4, bin(0xda442d24)[2:].zfill(32)):
            if y == '1':
                new5.append(x)
            else:
                new5.append(0)
        new5 = vector(new5)

        c6 = (new1 + new2 + c2 + c4 + new3 + new5)  # 32 bits

        self.state[pprev + 1] = c6  # 32 bits
        self.state[0] = pprev  # 4 bits

        return c6
        #return c6 - 1
        

#will treat state[1:] as arrays of 32 1 bit elements
F2 = GF(2)
P = PolynomialRing(F2, [f"x_{i}" for i in range(16*32)])
coefs = P.gens()
mp = dict()
for i in range(len(coefs)):
    mp[coefs[i]] = i

sym_state = [vector(coefs[32*i:32*(i+1)]) for i in range(len(coefs)//32)]
ss_prng = sage_sym_prng(sym_state)
state = [random.randint(0, 2^32) for _ in range(16)]
rng = Well512(state)

#what happens is that we have 8 consecutive outputs (or more), then a certain unknown distance, and then 8 more consecutive outputs 
outputs = [rng.clock() for _ in range(8)]
dist = random.randint(0, 256)
for _ in range(dist):
    rng.clock()

outputs += [rng.clock() for _ in range(8)]

dist2 = random.randint(0, 256)

for _ in range(dist):
    rng.clock()

outputs += [rng.clock() for _ in range(8)]


#IF YOU NEED TO BUILD ROWS.TXT, UNCOMMENT THIS AND COMMENT THE PART THAT READS FROM FILE
#AFTER FIRST ITERATION, RECOMMENT THIS
rows = []
rhs = []


for j in range(8):
    ls = ss_prng.clock()
    rs = outputs[j]
    for x, y in zip(ls, bin(rs+1)[2:].zfill(32)):
        j = x.monomials()
        row = [0 for _ in range(512)]
        for elem in j:
            row[mp[elem]] = 1
        rows.append(row)
        rhs.append(int(y))


#rhs is always the same
for j in range(8, 16):
    rs = outputs[j]
    for y in bin(rs+1)[2:].zfill(32):
        rhs.append(int(y))


import tqdm
temp_rows = []
#I precompute all of the rows
for ind in tqdm.tqdm(range(256 + 256)):
    ls = ss_prng.clock()
    for x in ls:
        j = x.monomials()
        row = [0 for _ in range(512)]
        for elem in j:
            row[mp[elem]] = 1
        temp_rows.append(row)


f = open("rows.txt", "w")
for elem in rows:
    f.write(str(elem) + "\n")

for elem in temp_rows:
    f.write(str(elem) + "\n")

f.close()


#dump this to precompute rows

rhs = []
for j in range(16):
    rs = outputs[j]
    for y in bin(rs+1)[2:].zfill(32):
        rhs.append(int(y))

f = open("rows.txt")
rows = []
for j in range(256):
    rows.append(eval(f.readline()))

temp_rows = []

for j in range(16640 - 256):
    temp_rows.append(eval(f.readline()))

print("here")
#now we brute the distances

for guess in range(256):
    try:
        choice = rows + temp_rows[32*guess:32*guess + 256]
        A = Matrix(GF(2), choice)
        aff = A.solve_right(vector(GF(2), rhs))
        for elem in A.right_kernel():
            x = aff + elem
            blocks = [x[32*i:32*(i+1)] for i in range(len(coefs)//32)]
            orig_state = [sum([int(xi)*2^(31-i) for i, xi in enumerate(blocks[j])]) for j in range(len(blocks))]

            temp_prng = Well512(list(map(int, orig_state)))
            for _ in range(8 + guess):
                temp_prng.clock()
            
            for j in range(256):
                if temp_prng.clock() == outputs[16]:
                    if temp_prng.clock() == outputs[17]:
                        print("found")
                        print(orig_state == state)
                        print(f"{orig_state = }")
                        print(f"{guess = }")
                        print(f"{dist = }")
                        input()
            
    except Exception as e:
        continue
