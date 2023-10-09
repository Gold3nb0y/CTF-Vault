#!/bin/bash

gcc -O0 client.c -o client -lpthread -lrt
gcc -O0 server.c -o server -lpthread -lrt
