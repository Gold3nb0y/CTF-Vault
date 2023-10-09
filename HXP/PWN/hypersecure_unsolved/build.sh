#!/bin/bash
#
gcc -o exploit -static exp.c 
nasm -f bin -o shellcode vm.asm
nasm -f bin -o shellcode2 vm2.asm
mv ./exploit ./filesystem
cp ./shellcode ./filesystem
cp ./shellcode2 ./filesystem
cd filesystem
find . -print0 | cpio --null -o --format=newc >../initramfs.cpio 

#cd ..

#docker build -t hypersecure .
#docker run -p 1234:1234 -it hypersecure /bin/bash
