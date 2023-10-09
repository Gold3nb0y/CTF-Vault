#!/bin/bash

gcc -o exploit -pthread -static exploit.c
mv ./exploit ./rootfs_dir
cd rootfs_dir
find . -print0 | cpio --null -o --format=newc >../rootfs
gzip -f ../rootfs
