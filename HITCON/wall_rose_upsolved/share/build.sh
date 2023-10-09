#!/bin/bash


if [ -n $1 ]
then
    echo "cross cache"
    gcc -o exploit -pthread -no-pie -static ../cross_cache.c
else
    gcc -o exploit -pthread -static ../exploit.c
fi
mv ./exploit ./initramfs/home/user/
cd initramfs
find . -print0 | cpio --null -o --format=newc > ../initramfs.cpio
gzip -f ../initramfs.cpio
