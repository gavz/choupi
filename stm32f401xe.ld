MEMORY
{
    FLASHLOADER (rx) : ORIGIN = 0x08000000, LENGTH = 16K
    FLASHCODE (rx) : ORIGIN = 0x08060000, LENGTH = 128K
    RAM (rw) : ORIGIN = 0x20000000, LENGTH = 96K
}

STACK_SIZE = 0x800;
HEAP_SIZE = 0x800;
SHARED_RW_SIZE = 0x1000;
ARGBUF_SIZE = 0x400;

ENTRY(Reset_Handler)

SECTIONS
{
    /***************************************************\
     * ISR vector that must be kept at byte 0 in flash *
    \***************************************************/
    .flashloader :
    {
        KEEP(*(.isr_vector))
    } > FLASHLOADER

    /*************\
     * Main code *
    \*************/
    .text :
    {
        *(.text*)

        KEEP(*(.init))
        KEEP(*(.fini))

        *(.rodata*)
    } > FLASHCODE

    /****************************************************\
     * Unwinding metadata (for future linking with C++) *
    \****************************************************/
    .ARM.extab :
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > FLASHCODE
    .ARM.exidx :
    {
    __exidx_start = .;
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > FLASHCODE
    __exidx_end = .;
    dottext_end_addr = .;

    /*********************\
     * OS stack and heap *
    \*********************/
    .stack_and_heap :
    {
        stack_lowest = .;
        . += STACK_SIZE;
        stack_highest = .;
        _estack = .;
        heap_begin = .;
        . += HEAP_SIZE;
        heap_end = .;
        heap_size = heap_end - heap_begin;
    } > RAM

    mpu_ospriv_start = ADDR(.stack_and_heap);
    mpu_ospriv_size = SIZEOF(.stack_and_heap);
    ASSERT(mpu_ospriv_size == (1 << LOG2CEIL(mpu_ospriv_size)),
           "OS-private region must be sized a power of two")
    /* Somehow without these lines, ld considers start & (size - 1) as a symbol
     * relocated on top of RAM, hence returning
     * ORIGIN(RAM) + (start - ORIGIN(RAM)) & (size - 1), which is not what is
     * expected. Adding these temporaries seems to make things work.
     */
    mpu_ospriv_mask = mpu_ospriv_size - 1;
    mpu_ospriv_shouldbezero = mpu_ospriv_start & mpu_ospriv_mask;
    ASSERT(mpu_ospriv_shouldbezero == 0,
           "OS-private region must be naturally aligned")

    /**************************************\
     * Shared buffer for argument passing *
    \**************************************/
    .shared_rw :
    {
        KEEP(*(.data._impure_ptr*))
        KEEP(*(*eh_globals))
        KEEP(*(*__terminate_handler*))
        KEEP(*(*__unexpected_handler*))
        KEEP(*(*emergency_pool*))
        mpu_shared_rw_start_to_clean = .;
        . += SHARED_RW_SIZE - mpu_shared_rw_start_to_clean ;
    } > RAM

    mpu_shared_rw_start = ADDR(.shared_rw);
    mpu_shared_rw_size = SIZEOF(.shared_rw);
    ASSERT(mpu_shared_rw_size == (1 << LOG2CEIL(mpu_shared_rw_size)),
           "Shared-RW must be sized a power of two")

    /* See mpu_ospriv comment */
    mpu_shared_rw_mask = mpu_shared_rw_size - 1;
    mpu_shared_rw_shouldbezero = mpu_shared_rw_start & mpu_shared_rw_mask;
    ASSERT(mpu_shared_rw_shouldbezero == 0,
           "Shared-RW is not naturally aligned")

    mpu_argbuf_size = ARGBUF_SIZE;

    /****************************\
     * Data to be copied in RAM *
    \****************************/
    .shared_ro : AT (dottext_end_addr)
    {
        *(.shared_ro*)
    }

    mpu_shared_ro_start = ADDR(.shared_ro);
    mpu_shared_ro_filled_size = SIZEOF(.shared_ro);
    mpu_shared_ro_size_exact = 1 << LOG2CEIL(mpu_shared_ro_filled_size);
    mpu_shared_ro_size = MAX(32, mpu_shared_ro_size_exact);
    /* See mpu_ospriv comment */
    mpu_shared_ro_mask = mpu_shared_ro_size - 1;
    mpu_shared_ro_shouldbezero = mpu_shared_ro_start & mpu_shared_ro_mask;
    ASSERT(mpu_shared_ro_shouldbezero == 0,
           "Shared-RO is not naturally aligned")

    .shared_ro_fill :
    {
        . += mpu_shared_ro_size - mpu_shared_ro_filled_size;
    } > RAM

    .data :
    {
        _sdata = .; /* Used by startup code by stm */

        *(.data*)

        . = ALIGN(4);
        _edata = .; /* Used by startup code by stm */
    } > RAM

    _sidata = LOADADDR(.data); /* Used by startup code by stm */

    .bss :
    {
        . = ALIGN(4);
        _sbss = .; /* Used by startup code by stm */

        *(.bss*)
        *(COMMON)

        . = ALIGN(4);
        _ebss = .; /* Used by startup code by stm */
    } > RAM


    /*******************************\
     * Reserved space for contexts *
    \*******************************/
    mpu_contexts_start = .;
    mpu_contexts_already_filled = mpu_contexts_start - ORIGIN(RAM);
    .reserved_contexts :
    {
        . = LENGTH(RAM) - mpu_contexts_already_filled;
    }
    mpu_contexts_size = . - mpu_contexts_start;
}
