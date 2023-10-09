OUTPUT_ARCH("riscv")
ENTRY(_start)

PHDRS {
    r-x PT_LOAD FLAGS(5);
    r-- PT_LOAD FLAGS(4);
    rw- PT_LOAD FLAGS(6);
}

SECTIONS {

    _kernel_start = .;

    /* -------- Segment: r-x -------- */

    .text ALIGN(0x1000) : {
        _seg_rx_start = .;
        _text_start = .;
        *(.text.start .text.start.*)
        *(.text .text.*)
        _text_end = .;
        _seg_rx_end = .;
    } :r-x

    /* -------- Segment: r-- -------- */

    .rela.dyn ALIGN(0x1000) : {
        _seg_r_start = .;
        _rela_start = .;
        *(.rela .rela.*)
        _rela_end = .;
    } :r--

    .rodata : {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
        _seg_r_end = .;
    }

    /* -------- Segment: rw- -------- */

    .data ALIGN(0x1000) : {
        _seg_rw_start = .;
        _data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        _data_end = .;
    } :rw-

    .bss (NOLOAD) : {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        _bss_end = .;
        _seg_rw_end = .;
    }

    .stack (NOLOAD) : {
        _stack_start = .;
        . = . + 0x10000;
        _stack_end = .;
    }

    _kernel_end = .;

    /* -------- No segment -------- */

    /DISCARD/ : {
        *(.dynamic) *(.dynsym) *(.dynstr) *(.hash) *(.gnu.hash)
    }

    .rel.dyn : {
        *(.rel.dyn)
    }
    ASSERT(SIZEOF(.rel.dyn) == 0, "Section .rel.dyn should be empty")

    .got : {
        *(.got)
    }
    ASSERT(SIZEOF(.got) == 0, "Section .got should be empty")

    .got.plt : {
        *(.got.plt)
    }
    ASSERT(SIZEOF(.got.plt) == 0, "Section .got.plt should be empty")

    .plt : {
        *(.plt) *(.plt.*)
    }
    ASSERT(SIZEOF(.plt) == 0, "Section .plt should be empty")
}

ASSERT(_kernel_start == 0, "Kernel should start at virtual address zero")
ASSERT(_start == 0, "Entrypoint should be at the start")
