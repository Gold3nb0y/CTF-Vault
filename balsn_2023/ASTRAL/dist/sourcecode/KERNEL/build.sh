#!/bin/bash

gcc -masm=intel -nostdlib -fno-builtin -fno-stack-protector entry.S panic.S syscall.S interruptEntry.S elf.c hypercall.c kernel.c memory.c syscall.c applet.c -o custom_kernel
./upload.sh dcdcebbb88a2 custom_kernel
