#!/bin/bash


gcc -o exploit ./exploit.c
mv ./exploit ./initramfs/
cd initramfs
find . -print0 | cpio --null -o --format=newc > ../initramfs.cpio
