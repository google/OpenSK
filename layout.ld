/* Userland Generic Layout
 *
 * Currently, due to incomplete ROPI-RWPI support in rustc (see
 * https://github.com/tock/libtock-rs/issues/28), this layout implements static
 * linking. An application init script must define the FLASH and SRAM address
 * ranges as well as MPU_MIN_ALIGN before including this layout file.
 *
 * Here is a an example application linker script to get started:
 *     MEMORY {
 *         /* FLASH memory region must start immediately *after* the Tock
 *          * Binary Format headers, which means you need to offset the
 *          * beginning of FLASH memory region relative to where the
 *          * application is loaded.
 *         FLASH (rx) : ORIGIN = 0x10030, LENGTH = 0x0FFD0
 *         SRAM (RWX) : ORIGIN = 0x20000, LENGTH = 0x10000
 *     }
 *     STACK_SIZE = 2048;
 *     MPU_MIN_ALIGN = 8K;
 *     INCLUDE ../libtock-rs/layout.ld
 */

ENTRY(_start)

SECTIONS {
    /* Section for just the app crt0 header.
     * This must be first so that the app can find it.
     */
    .crt0_header :
    {
        _beginning = .; /* Start of the app in flash. */
        /**
         * Populate the header expected by `crt0`:
         *
         *  struct hdr {
         *    uint32_t got_sym_start;
         *    uint32_t got_start;
         *    uint32_t got_size;
         *    uint32_t data_sym_start;
         *    uint32_t data_start;
         *    uint32_t data_size;
         *    uint32_t bss_start;
         *    uint32_t bss_size;
         *    uint32_t reldata_start;
         *    uint32_t stack_size;
         *  };
         */
        /* Offset of GOT symbols in flash */
        LONG(LOADADDR(.got) - _beginning);
        /* Offset of GOT section in memory */
        LONG(_got);
        /* Size of GOT section */
        LONG(SIZEOF(.got));
        /* Offset of data symbols in flash */
        LONG(LOADADDR(.data) - _beginning);
        /* Offset of data section in memory */
        LONG(_data);
        /* Size of data section */
        LONG(SIZEOF(.data));
        /* Offset of BSS section in memory */
        LONG(_bss);
        /* Size of BSS section */
        LONG(SIZEOF(.bss));
        /* First address offset after program flash, where elf2tab places
         * .rel.data section */
        LONG(LOADADDR(.endflash) - _beginning);
        /* The size of the stack requested by this application */
        LONG(STACK_SIZE);
        /* Pad the header out to a multiple of 32 bytes so there is not a gap
         * between the header and subsequent .data section. It's unclear why,
         * but LLD is aligning sections to a multiple of 32 bytes. */
        . = ALIGN(32);
    } > FLASH =0xFF

    /* Text section, Code! */
    .text :
    {
        . = ALIGN(4);
        _text = .;
        KEEP (*(.start))
        *(.text*)
        *(.rodata*)
        KEEP (*(.syscalls))
        *(.ARM.extab*)
        . = ALIGN(4); /* Make sure we're word-aligned here */
        _etext = .;
    } > FLASH =0xFF

    /* Application stack */
    .stack :
    {
        . = . + STACK_SIZE;

	_stack_top_unaligned = .;
        . = ALIGN(8);
	_stack_top_aligned = .;
    } > SRAM

    /* Data section, static initialized variables
     *  Note: This is placed in Flash after the text section, but needs to be
     *  moved to SRAM at runtime
     */
    .data : AT (_etext)
    {
        . = ALIGN(4); /* Make sure we're word-aligned here */
        _data = .;
        KEEP(*(.data*))
        . = ALIGN(4); /* Make sure we're word-aligned at the end of flash */
    } > SRAM

    /* Global Offset Table */
    .got :
    {
        . = ALIGN(4); /* Make sure we're word-aligned here */
        _got = .;
        *(.got*)
        *(.got.plt*)
        . = ALIGN(4);
    } > SRAM

    /* BSS section, static uninitialized variables */
    .bss :
    {
        . = ALIGN(4); /* Make sure we're word-aligned here */
        _bss = .;
        KEEP(*(.bss*))
        *(COMMON)
        . = ALIGN(4);
    } > SRAM

    /* End of flash. */
    .endflash :
    {
    } > FLASH

    /* ARM Exception support
     *
     * This contains compiler-generated support for unwinding the stack,
     * consisting of key-value pairs of function addresses and information on
     * how to unwind stack frames.
     * https://wiki.linaro.org/KenWerner/Sandbox/libunwind?action=AttachFile&do=get&target=libunwind-LDS.pdf
     *
     * .ARM.exidx is sorted, so has to go in its own output section.
     *
     * __NOTE__: It's at the end because we currently don't actually serialize
     * it to the binary in elf2tbf. If it was before the RAM sections, it would
     * through off our calculations of the header.
     */
    PROVIDE_HIDDEN (__exidx_start = .);
    .ARM.exidx :
    {
      /* (C++) Index entries for section unwinding */
      *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > FLASH
    PROVIDE_HIDDEN (__exidx_end = .);
}

ASSERT((_stack_top_aligned - _stack_top_unaligned) == 0, "
STACK_SIZE must be 8 byte multiple")
