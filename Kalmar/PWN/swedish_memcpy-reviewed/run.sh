#!/bin/sh
OUT="$(mktemp /tmp/disk.redacted.bin.XXXXXXXXXX)"
cp ./disk.redacted.bin "$OUT"

qemu-system-x86_64 \
    -monitor /dev/null \
    -drive format=raw,file="$OUT" \
    -serial stdio \
    -m 512M \
    -display none \
    -s \
    -no-reboot #< sdk/main.bin

rm "$OUT"

