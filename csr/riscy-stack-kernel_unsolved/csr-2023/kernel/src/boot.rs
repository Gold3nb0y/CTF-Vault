//! Startup code

use core::{arch::asm, ops::Range, ptr, slice};

use crate::{addr::VirtAddr, main, print::println, trap, util::local_addr_of, vm};

/// Entrypoint of the kernel, invoked by the firmware. Placed at the beginning of the `.text`
/// section by the linker script. Sets up the stack and calls into Rust code [`rust_entry`].
///
/// # Safety
///
/// May only be invoked by the previous boot stage, must not be called manually.
#[link_section = ".text.start"]
#[no_mangle]
#[naked]
unsafe extern "C" fn _start() -> ! {
    // Safety: We respect ABI when calling into rust
    unsafe {
        asm!(
            // Set up the stack
            "lla sp, _stack_end",
            // Call into rust
            "j {rs}",
            rs = sym rust_entry,
            options(noreturn),
        );
    }
}

/// First Rust code that is executed after entry. Initializes the runtime and invokes [`main`].
///
/// # Safety
///
/// May only be invoked from the assembly entrypoint.
unsafe extern "C" fn rust_entry(cpu: usize, dtb: *const u8) -> ! {
    // Apply relocations before doing anything else. Safety: We are still booting.
    unsafe { apply_relocations() };

    // Get extends of `.bss` section
    let bss_start = local_addr_of!(_bss_start: *mut u8);
    let bss_end = local_addr_of!(_bss_end: *mut u8);
    // Zero `.bss`. Safety: Linker script places `.bss` here
    unsafe { ptr::write_bytes(bss_start, 0, bss_end.sub_ptr(bss_start)) };

    println!("\n\nBooting on CPU #{cpu}, DTB @ {dtb:?}");

    // Initialize virtual memory system. Safety: Only called on startup.
    unsafe { vm::init(dtb) };
}

/// Invoked by [`vm::init`] after switching to virtual memory.
///
/// # Safety
///
/// May only be invoked once during startup.
pub unsafe fn post_vm_entry(int_stack: VirtAddr) -> ! {
    // Apply relocations for relocated kernel image. Safety: We are still booting.
    unsafe { apply_relocations() };

    // Initialize trap handling. Safety: Only called on startup.
    unsafe { trap::init(int_stack) };

    // Invoke main
    println!("Boot finished");
    main();

    println!("\n\nmain function returned, halting");
    halt();
}

/// Applies all relocations from the `.rela.dyn` section.
///
/// # Safety
///
/// May only be called during boot.
unsafe fn apply_relocations() {
    /// ELF relocation entry, with addend
    #[repr(C)]
    struct Rela {
        /// Virtual address of target
        offset: usize,
        /// Type and symbol of relocation
        info:   usize,
        /// Addend used in calculation
        addend: usize,
    }

    // Get slice of all relocations
    let relas = Range {
        start: local_addr_of!(_rela_start: *const Rela),
        end:   local_addr_of!(_rela_end: *const Rela),
    };
    // Safety: `_rela_start` and `_rela_end` delimit the `.rela.dyn` section
    let relas = unsafe { slice::from_ptr_range(relas) };

    // Get actual base address
    let load = local_addr_of!(_kernel_start: *mut u8);

    // Loop over relocations
    for rela in relas {
        // Only handle `R_RISCV_RELATIVE` for now
        assert!(rela.info == 3);
        // Calculate final value
        let val = load.addr() + rela.addend;
        // Write value. Safety: Offset is within the binary.
        unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            load.add(rela.offset).cast::<usize>().write_volatile(val);
        };
    }
}

/// Halts the current hart by looping endlessly
pub fn halt() -> ! {
    loop {
        // Safety: WFI instruction is always safe
        unsafe { asm!("wfi") };
    }
}
