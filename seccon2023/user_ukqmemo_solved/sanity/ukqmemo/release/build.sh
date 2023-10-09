#!/bin/bash

gcc -o exp -pthread -static k_exploit.c
mv ./exp ./rootfs/
cd rootfs
find . -print0 | cpio --null -o --format=newc > ../rootfs.cpio
gzip -f ../rootfs.cpio
