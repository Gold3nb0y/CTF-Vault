//! Trap handling

use core::{arch::asm, mem::size_of};

use crate::{
    addr::VirtAddr,
    csr, interrupt, syscall,
    vm::{STACK_BASE, STACK_SIZE},
};

/// Mask of the bits that specify the trap type (exception or interrupt) in the `scause` value
const CAUSE_TYPE: usize = 1 << (usize::BITS - 1);
/// *Supervisor Previous Interrupt Enabled* bit of the *Supervisor Status Register* CSR
const SSTATUS_SPIE: usize = 0b1 << 5;
/// *Supervisor Previous Privilege* bit of the *Supervisor Status Register* CSR
const SSTATUS_SPP: usize = 0b1 << 8;

/// Trap frame. Contains information about the trap and all register values on entering the trap.
/// Where applicable, values will be restored from the trap frame when returning from the trap.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct TrapFrame<'a> {
    /// Address of the trapping instruction
    pub epc:       usize,
    /// Cause of the trap
    pub cause:     usize,
    /// Trap-specific value, e.g. address of an access fault
    pub tval:      usize,
    /// Previous privilege mode, i.e. whether the trap comes from supervisor mode
    pub prev_priv: bool,
    /// Whether interrupts were previously enabled
    pub prev_int:  bool,
    /// Saved registers
    pub regs:      &'a mut SavedRegs,
}

/// Register values saved on entering a trap
#[repr(C)]
#[derive(Debug)]
pub struct SavedRegs {
    /// General-purpose registers
    pub regs_gp: [usize; 31],
}

/// Initializes trap handling: Sets up a trap handler and enables interrupts.
///
/// Requires an interrupt stack that's used to set up the trap frame. The actual trap handling might
/// switch to the main kernel stack, for example when handling system calls.
///
/// # Safety
///
/// May only be called during boot.
pub unsafe fn init(stack_top: VirtAddr) {
    // Stack pointer used by trap handler
    let stack = stack_top - size_of::<SavedRegs>();
    // Safety: Writing `sscratch` is always safe
    unsafe { csr::write!("sscratch", stack.virt) };

    // Safety: `trap_entry` is a valid trap handler and aligned to 4 byte
    unsafe { csr::write!("stvec", trap_entry) };
    // Enable interrupts. Safety: Trap handler is already set up.
    unsafe { interrupt::set_enabled(true) };
}

/// Trap handler, invoked when an exception or an interrupt occurs. Saves the current register state
/// and invokes Rust code [`trap_handler`] to handle the trap.
///
/// # Safety
///
/// May only be invoked by the EEI, must not be called manually.
#[repr(align(4))]
#[naked]
unsafe extern "C" fn trap_entry() -> ! {
    // Safety: Registers are correctly saved on stack and we respect ABI when calling into rust
    unsafe {
        asm!(
            // Switch pointer to reg state into `x1`
            "csrrw x1, sscratch, x1",
            // Save `x2`
            "sd x2, 8(x1)",
            // Put saved `x1` into `x2` and save it, and restore scratch
            "csrrw x2, sscratch, x1",
            "sd x2, 0(x1)",
            // Save all remaining registers
            "sd x3,  0x10(x1)",
            "sd x4,  0x18(x1)",
            "sd x5,  0x20(x1)",
            "sd x6,  0x28(x1)",
            "sd x7,  0x30(x1)",
            "sd x8,  0x38(x1)",
            "sd x9,  0x40(x1)",
            "sd x10, 0x48(x1)",
            "sd x11, 0x50(x1)",
            "sd x12, 0x58(x1)",
            "sd x13, 0x60(x1)",
            "sd x14, 0x68(x1)",
            "sd x15, 0x70(x1)",
            "sd x16, 0x78(x1)",
            "sd x17, 0x80(x1)",
            "sd x18, 0x88(x1)",
            "sd x19, 0x90(x1)",
            "sd x20, 0x98(x1)",
            "sd x21, 0xa0(x1)",
            "sd x22, 0xa8(x1)",
            "sd x23, 0xb0(x1)",
            "sd x24, 0xb8(x1)",
            "sd x25, 0xc0(x1)",
            "sd x26, 0xc8(x1)",
            "sd x27, 0xd0(x1)",
            "sd x28, 0xd8(x1)",
            "sd x29, 0xe0(x1)",
            "sd x30, 0xe8(x1)",
            "sd x31, 0xf0(x1)",

            // Setup stack and call into rust trap handler
            "mv sp, x1",
            "mv a0, x1",
            "jal {rs}",

            // Get reg state back into `x1`
            "mv x1, sp",
            // Restore registers, except `x1`
            "ld x2,  0x08(x1)",
            "ld x3,  0x10(x1)",
            "ld x4,  0x18(x1)",
            "ld x5,  0x20(x1)",
            "ld x6,  0x28(x1)",
            "ld x7,  0x30(x1)",
            "ld x8,  0x38(x1)",
            "ld x9,  0x40(x1)",
            "ld x10, 0x48(x1)",
            "ld x11, 0x50(x1)",
            "ld x12, 0x58(x1)",
            "ld x13, 0x60(x1)",
            "ld x14, 0x68(x1)",
            "ld x15, 0x70(x1)",
            "ld x16, 0x78(x1)",
            "ld x17, 0x80(x1)",
            "ld x18, 0x88(x1)",
            "ld x19, 0x90(x1)",
            "ld x20, 0x98(x1)",
            "ld x21, 0xa0(x1)",
            "ld x22, 0xa8(x1)",
            "ld x23, 0xb0(x1)",
            "ld x24, 0xb8(x1)",
            "ld x25, 0xc0(x1)",
            "ld x26, 0xc8(x1)",
            "ld x27, 0xd0(x1)",
            "ld x28, 0xd8(x1)",
            "ld x29, 0xe0(x1)",
            "ld x30, 0xe8(x1)",
            "ld x31, 0xf0(x1)",
            // Restore `x1`
            "ld x1, 0(x1)",
            // Return from trap
            "sret",
            rs = sym trap_handler,
            options(noreturn),
        );
    }
}

/// Rust part of the trap handler. Panics on exceptions, continues execution on interrupts.
///
/// # Safety
///
/// May only be invoked by [`trap_entry`], must not be called manually.
unsafe extern "C" fn trap_handler(regs: &mut SavedRegs) {
    // Read status to obtain some information about the trap. Safety: Reading this register is
    // always safe.
    let status = unsafe { csr::read!("sstatus") };
    // Read rest of trap information from CSRs to complete trap frame. Safety: Reading these
    // registers is always safe.
    let mut frame = unsafe {
        TrapFrame {
            epc: csr::read!("sepc"),
            cause: csr::read!("scause"),
            tval: csr::read!("stval"),
            prev_priv: status & SSTATUS_SPP != 0,
            prev_int: status & SSTATUS_SPIE != 0,
            regs,
        }
    };

    if frame.cause & CAUSE_TYPE == 0 {
        // Exception

        if frame.cause == 8 {
            // Handle syscalls on kernel stack. Safety: We are on the interrupt stack.
            unsafe { invoke_on_kernel_stack(&mut frame, syscall::handle) };
        } else if frame.cause == 15 && frame.tval == 0x123 {
            // Transition to userspace
            assert!(frame.prev_int);
            frame.prev_priv = false;
            frame.epc = frame.regs.regs_gp[9];
            frame.regs.regs_gp.fill(0);
        } else {
            // Unexpected exception: Panic
            let msg = match frame.cause {
                0 => "Instruction address misaligned",
                1 => "Instruction access fault",
                2 => "Illegal instruction",
                3 => "Breakpoint",
                4 => "Load address misaligned",
                5 => "Load access fault",
                6 => "Store/AMO address misaligned",
                7 => "Store/AMO access fault",
                9 => "Environment call from S-mode",
                12 => "Instruction page fault",
                13 => "Load page fault",
                15 => "Store/AMO page fault",
                _ => "Unknown",
            };
            panic!("{msg} exception: {frame:#x?}");
        }
    } else {
        // Interrupt: Resume execution
    }

    // Write modified trap information back to CSRs. Safety: Trap frame is valid.
    unsafe {
        csr::write!("sepc", frame.epc);

        if frame.prev_priv {
            csr::set!("sstatus", SSTATUS_SPP);
        } else {
            csr::clear!("sstatus", SSTATUS_SPP);
        }

        if frame.prev_int {
            csr::set!("sstatus", SSTATUS_SPIE);
        } else {
            csr::clear!("sstatus", SSTATUS_SPIE);
        }
    }
}

/// Invoke the given function after switching to the kernel stack and enabling interrupts.
///
/// # Safety
///
/// May only be called from the interrupt stack.
unsafe fn invoke_on_kernel_stack(frame: &mut TrapFrame, fun: fn(&mut TrapFrame)) {
    /// Enables interrupts and invokes the given function
    #[allow(improper_ctypes_definitions)]
    unsafe extern "C" fn trampoline(frame: &mut TrapFrame, fun: fn(&mut TrapFrame)) {
        // Safety: We are on the kernel stack now
        unsafe { interrupt::set_enabled(true) };
        fun(frame);
    }

    // Safety: We restore the stack and respect ABI when calling the function
    unsafe {
        asm!(
            // Save old stack pointer
            "mv s2, sp",
            // Switch to kernel stack
            "li sp, {stack}",
            // Invoke function
            "jal {tramp}",
            // Restore stack
            "mv sp, s2",
            stack = const STACK_BASE.virt + STACK_SIZE,
            tramp = sym trampoline,
            in("a0") frame,
            in("a1") fun,
            out("s2") _,
            clobber_abi("C"),
        );
    }
}
