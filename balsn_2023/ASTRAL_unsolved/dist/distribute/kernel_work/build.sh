#!/bin/bash
#
gcc -masm=intel -fno-stack-protector -nostdlib -fno-builtin entry.S exp.c applet_helper.c syscall.c lib.c -o exploit
./upload.sh dcdcebbb88a2 exploit
