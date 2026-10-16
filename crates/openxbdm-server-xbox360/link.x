ENTRY(_start)

/* The image must end below 0x92000000, where the system shell loads.
   Sections are packed on 4 KB pages (the image uses SMALL_PAGES). */
SECTIONS {
    . = 0x91f01000;
    .text : {
        *(.text._start)
        *(.text .text.*)
    }
    . = ALIGN(4);
    .xthunks : { *(.xthunks .xthunks.*) }

    . = ALIGN(0x1000);
    .rodata : { *(.rodata .rodata.*) }

    . = ALIGN(0x1000);
    .data : { *(.data .data.*) *(.sdata .sdata.*) }
    . = ALIGN(4);
    .xvars : { *(.xvars .xvars.*) }

    . = ALIGN(0x1000);
    .bss : { *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) }

    /* Export records: kept as GC roots, read by xex-link, not loaded. */
    . = ALIGN(4);
    .xexports : { KEEP(*(.xexports)) }

    /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) *(.comment) *(.note .note.*) }
}
