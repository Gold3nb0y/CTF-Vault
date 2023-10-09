#!/usr/bin/python3

from Crypto.PublicKey import RSA

n=0xa9e7da28ebecf1f88efe012b8502122d70b167bdcfa11fd24429c23f27f55ee2cc3dcd7f337d0e630985152e114830423bfaf83f4f15d2d05826bf511c343c1b13bef744ff2232fb91416484be4e130a007a9b432225c5ead5a1faf02fa1b1b53d1adc6e62236c798f76695bb59f737d2701fe42f1fbf57385c29de12e79c5b3
check=0x17bb21949d5a0f590c6126e26dc830b51d52b8d0eb4f2b69494a9f9a637edb1061bec153f0c1d9dd55b1ad0fd4d58c46e2df51d293cdaaf1f74d5eb2f230568304eebb327e30879163790f3f860ca2da53ee0c60c5e1b2c3964dbcf194c27697a830a88d53b6e0ae29c616e4f9826ec91f7d390fb42409593e1815dbe48f7ed4
e=0x10001

m=0x945d86b04b2e7c7
m2=0x5de2
m3=0xa16b201cdd42ad70da249
m4=0x6d993121ed46b
m5=0x726fa7a7
m6=0x31e828d97a0874cff
m7=0x904a515


ms = [m,m2,m3,m4,m5,m6,m7]
def check(mes,num,c):
	n_here=0xa9e7da28ebecf1f88efe012b8502122d70b167bdcfa11fd24429c23f27f55ee2cc3dcd7f337d0e630985152e114830423bfaf83f4f15d2d05826bf511c343c1b13bef744ff2232fb91416484be4e130a007a9b432225c5ead5a1faf02fa1b1b53d1adc6e62236c798f76695bb59f737d2701fe42f1fbf57385c29de12e79c5b3
	sig = pow(mes,num,n_here)
	if hex(sig)==c:
		return True
	else:
		return False

real_msg = 0x686178656c696f6e

indexes = []

for i in range(100000):
	thing = real_msg + n*i
	for m in ms:
		if thing % m == 0:
			indexes.append(i)
			print(f'factor: {i}\nmessage: {hex(m)}')

sig = 0x3ea73715787028b52796061fb887a7d36fb1ba1f9734e9fd6cb6188e087da5bfc26c4bfe1b4f0cbfa0d693d4ac0494efa58888e8415964c124f7ef293a8ee2bc403cad6e9a201cdd442c102b30009a3b63fa61cdd7b31ce9da03507901b49a654e4bb2b03979aea0fab3731d4e564c3c30c75aa1d079594723b60248d9bdde50
for i in indexes:
	new_sig = (sig * i)%n
	print(hex(new_sig))
	print(hex(pow(sig,e,n)))

# def all_checks(num):
# 	if check(m2,num,check2) and check(m3,num,check3) and check(m4,num,check4) and check(m5,num,check5) and check(m6,num,check6) and check(m7,num,check7):
# 		return True
# 	else:
# 		return False

# potential = []
# sig = pow(m, 9123094871029384712, n)
# #print(hex(sig))
# count = 1

# looking_for = 0x686178656c696f6e
# ms.append(1)
# print(ms)


# for m in range(len(ms)):
# 	for j in range(len(ms)):
# 		for i in range(len(ms)):
# 			for x in range(len(ms)):
# 				for q in range(len(ms)):
# 					for y in range(len(ms)):
# 						for z in range(len(ms)):
# 							for a in range(len(ms)):
# 								for b in range(len(ms)):
# 									#for c in range(len(ms)):
# 										check = (ms[m]*ms[j]*ms[i]*ms[x]*ms[q]*ms[y]*ms[z]*ms[a]*ms[b])%n
# 										print(hex(check))
# 										#check = 0x686178656c696f6e
# 										if hex(check) == looking_for:
# 											print(f'lucky {ms[m]} {ms[j]} {ms[i]} {ms[x]} {ms[q]} {ms[y]} {ms[z]} {ms[a]} {ms[b]}')
# 											break;
# 										else:
# 											print(f'no luck {ms[m]} {ms[j]} {ms[i]} {ms[x]} {ms[q]} {ms[y]} {ms[z]} {ms[a]} {ms[b]}')

# checks = []
# for m in ms:
# 	checks.append((m*pow(looking_for,-1))%n)

# print(checks)
