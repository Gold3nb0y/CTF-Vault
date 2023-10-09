#!/usr/bin/env python3

with open("/dev/shm/lol1", "wb+") as dev:
    while True:
        string = input("thing to send to the waiting shared memory: ")
        print(f"debug {string}")
        dev.write(string.encode('utf-8'))

        dev.seek(0)
