#!/bin/bash
#
gcc -o exploit -static exp.c 
mv ./exploit ./rootfs
cd rootfs
find . -print0 | cpio --null -o --format=newc >../rootfs.cpio 
