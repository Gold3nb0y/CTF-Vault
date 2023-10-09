#!/bin/sh

cd $(dirname $0)
LD_LIBRARY_PATH=./qemu-bundle/lib exec ./qemu-system-x86_64 \
    -device memo-persist,ram=false,plimit=8 \
    -monitor /dev/null \
    -m 256M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=1 oops=panic panic=-1 pti=on nokaslr" \
    -no-reboot \
    -cpu kvm64,smap,smep \
    -initrd rootfs.cpio.gz \
    -net nic,model=virtio \
    -net user \
    -s
