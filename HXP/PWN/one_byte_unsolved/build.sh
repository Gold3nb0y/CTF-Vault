#!/bin/bash
#
gcc -o exploit -static exp.c 
mv ./exploit ./filesystem
cd filesystem
find . -print0 | cpio --null -o --format=newc >../initramfs.cpio 
cd ..
gzip -f initramfs.cpio


