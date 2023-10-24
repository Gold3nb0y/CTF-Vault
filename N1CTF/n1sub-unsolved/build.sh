#!/bin/bash


gcc -o exploit -pthread -no-pie -static exploit.c
mv ./exploit ./rootfs
cd rootfs
find . -print0 | cpio --null -o --format=newc > ../rootfs.cpio
