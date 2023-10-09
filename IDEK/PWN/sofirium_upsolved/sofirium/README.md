Hello World!

This challenge includes a collection of scripts to improve iteration times by automating some stuff. 
There are a couple of scripts, but ignore most of them and use the makefile instead.
The Makefile is inside the src directory and uses relatives paths, so run make only inside the src directory. Here are the possible commands and their functions

make run
    - Starts up Qemu with the cpio archive; by default its the same as remote but edits to run.sh will affect it 
    - Mounts /tmp into /tmp/mnt( Can be changed by changing virtfs,path in run.sh)
    - The exploit flag can be used specific a C file to compile and add into the archive at /exploit
        - EX: make exploit=exploit.c will run qemu, compile exploit.c, and copy it into qemu's file system at /exploit 

make debug
    - Same as the run, except it also runs GDB in a separate tmux window
    - NOTE: Symbols will only be correct if kaslr is DISABLED

make build_initramfs
    - Rebuilds any changes to the file system in initramfs
    - NOTE: Script assumes that decompress.sh was already run to unpack the cpio archive to initramfs

make build_module
    - Will rebuild the kernel module, any changes to chall.c will be reflected here
    - NOTE: Set KDIR to the directory with the kernel source code
        - Source can be downloaded from https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.5.tar.xz 
    - NOTE: run build_initramfs afterward to include the module in the cpio archive 

Remote contains the Dockerfile of the remote setup

Happy Hacking!
