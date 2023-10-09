# Download Kernel Source code here, If you want to build yourself
KDIR="/home/ex/ctf/idek/tofu/linux-6.0.15"
obj-m += chall.o
MY_CFLAGS += -g -DDEBUG -Werror
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

# Exploit logic is contained in run.sh, to pass an exploit use command line arg `exploit`
# make (run|debug) exploit=exploit.c
# Unpack the cpio to a directory called initramfs 

run:
	../run.sh ../initramfs.cpio $(exploit)

debug:
	tmux split-window -h "sudo gdb ../vmlinux -x ../gdb.sh "
	$(MAKE) run 

build_module:
	make -C $(KDIR) M=$(PWD) -Werror modules 
	EXTRA_CFLAGS="$(MY_CFLAGS)"
	cp ./chall.ko ../initramfs/

build_initramfs:
	cd ../initramfs && find . | cpio -H newc -ov -F ../initramfs.cpio 2> /dev/null
