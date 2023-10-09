#!/bin/bash
#
gcc -o exploit -static exp.c 
mv ./exploit ./system
cd system
find . -print0 | cpio --null -o --format=newc >../init.cpio 
