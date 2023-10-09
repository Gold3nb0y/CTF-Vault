#!/bin/sh
qemu-system-x86_64 \
    -kernel ./bzImage \
    -initrd ./rootfs.gz  \
    -append 'console=ttyS0 nokaslr loglevel=3 oops=panic panic=1' \
    -no-reboot \
    -s \
    -nographic
