global _start

section .text

;ptrace syscall
_start:

	
	
	;int execve(const char *filename, char *const argv[],char *const envp[])
	xor 	rsi,	rsi			;clear rsi
	push	rsi				;push null on the stack
	mov 	rdi,	0x72656469766f7270	 ;/bin//sh in reverse order
	push	rdi
    mov     rdi,    0x2f2e
    push    rdi

	push	rsp		
	pop	rdi				;stack pointer to /bin//sh
	mov 	al,	59			;sys_execve
	cdq					;sign extend of eax
	syscall


