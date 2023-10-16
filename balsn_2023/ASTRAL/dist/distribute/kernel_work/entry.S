.globl _start, hlt
.extern lolMain
.intel_syntax noprefix
_start:
  call lolMain
hlt:
  hlt
  jmp hlt
