#!/bin/bash
#
gcc -o exploit -static exp.c 
mv ./exploit ./file_system
cd file_system
find . -print0 | cpio --null -o --format=newc >../init.cpio 

cd ..

docker build -t fipc .
docker run -dp 10003:10003 -p 1234:1234 fipc
