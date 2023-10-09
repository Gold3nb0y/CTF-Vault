/bin/busybox --install -s /bin
stty raw -echo
chown -R 0:0 /
mount -a
modprobe virtio
modprobe virtio_ring
modprobe virtio_pci
modprobe virtio_blk
chmod 400 /dev/vda
insmod /one_byte.ko
echo 1 > /proc/sys/kernel/dmesg_restrict
echo 1 > /proc/sys/kernel/kptr_restrict
echo 3 > /proc/sys/kernel/perf_event_paranoid
echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled
echo 0 > /proc/sys/vm/unprivileged_userfaultfd
echo 0 > /proc/sys/user/max_user_namespaces
chmod 400 /proc/kallsyms
chmod 600 /dev/kmsg
[ -e /dev/vdb ] && cat /dev/vdb > /bin/pwn && chmod 555 /bin/pwn # hxp <3 you
