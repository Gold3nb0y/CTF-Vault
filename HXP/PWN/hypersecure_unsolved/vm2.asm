bits 64

section .text

global _start

_start:
    mov rdx, 0x9001
    vmmcall
