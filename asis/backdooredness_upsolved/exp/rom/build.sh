#!/bin/bash
#
cc65 -o pwn.s pwn.c
ca65 -o main.o main.s
ca65 -o header.o header.s 
ca65 -o pwn.o pwn.s
ld65 -C link.x pwn.o main.o header.o -o chef.nes
