    .export _bka
    .export _bkx
    .export _nop

_bka:
    .byte $13
    rts

_bkx:
    .byte $37
    rts

_nop:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rts
