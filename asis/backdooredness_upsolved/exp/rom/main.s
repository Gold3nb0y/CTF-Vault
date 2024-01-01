.include "defs.s"
.import _start_c
.export _brk
.export _brx

.code

;;; ----------------------------------------------------------------------------
;;; Reset handler

.proc reset
	sei			; Disable interrupts
	cld			; Clear decimal mode
	ldx #$ff
	txs			; Initialize SP = $FF
	inx
	stx PPUCTRL		; PPUCTRL = 0
	stx PPUMASK		; PPUMASK = 0
	stx PUTC		; APUSTATUS = 0

	;; PPU warmup, wait two frames, plus a third later.
	;; http://forums.nesdev.com/viewtopic.php?f=2&t=3958
:	bit PPUSTATUS
	bpl :-
:	bit PPUSTATUS
	bpl :-

	;; Zero ram.
	;txa
	;sta $000, x
	;sta $100, x
	;sta $200, x
	;sta $300, x
	;sta $400, x
	;sta $500, x
	;sta $600, x
	;sta $700, x
	;inx
	;bne :-

	;; Final wait for PPU warmup.
;:	bit PPUSTATUS
;	bpl :-
;
;	ldx #$41		; enable pulse 1
;	stx PUTC
;	stx PUTC
;    
;    ldy #$BB
;    ldy #$DD
;
;    ldx #$0
;
;    ldy #$EE
;	;; Write char to output
;
;
;    lda #$07
;    .byte $13
;    lda #$80
;    .byte $13
;    lda #$44
;    .byte $37
;
;    ldy $780
;    sty PUTC
;
;	ldx #$43		; enable pulse 1
;	stx PUTC
;	stx PUTC
;	stx PUTC
    jsr _start_c

forever:
	jmp forever
.endproc

_brk:
    .byte $13
    rts

_brx:
    .byte $37
    rts

;;; ----------------------------------------------------------------------------
;;; NMI (vertical blank) handler

.proc nmi
	rti
.endproc

;;; ----------------------------------------------------------------------------
;;; IRQ handler

.proc irq
	rti
.endproc

;;; ----------------------------------------------------------------------------
;;; Vector table

.segment "VECTOR"
.addr nmi
.addr reset
.addr irq

;;; ----------------------------------------------------------------------------
;;; Empty CHR data, for now

.segment "CHR0a"
.segment "CHR0b"
