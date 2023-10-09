//! Manage and interact with usermode

use core::{arch::asm, ops::Range, ptr};

use crate::{addr::VirtAddr, csr, interrupt};

/// *User Big Endian* bit of the *Supervisor Status Register* CSR
const SSTATUS_UBE: usize = 0b1 << 6;
/// *Supervisor User Memory* bit of the *Supervisor Status Register* CSR
const SSTATUS_SUM: usize = 0b1 << 18;
/// *Make Executable Readable* bit of the *Supervisor Status Register* CSR
const SSTATUS_MXR: usize = 0b1 << 19;
/// *User XLEN* field of the *Supervisor Status Register* CSR
const SSTATUS_UXL: usize = 0b11 << 32;

/// Initializes CSRs in preparation of usermode.
///
/// # Safety
///
/// Must only be called once, after boot.
pub unsafe fn init() {
    // Modify `sstatus`
    interrupt::free(|| {
        // Safety: Reading `sstatus` is always safe
        let s = unsafe { csr::read!("sstatus") };
        // Clear UBE, SUM, MXR, UXL
        let s = s & !(SSTATUS_UBE | SSTATUS_SUM | SSTATUS_MXR | SSTATUS_UXL);
        // Set UXL to 2
        let s = s | (2 << 32);
        // Safety: We write a properly modified value
        unsafe { csr::write!("sstatus", s) };
    });
}

/// Copies data from userspace. Returns the number of remaining bytes on failure.
pub fn copy_from_user(src: VirtAddr, dst: &mut [u8]) -> Result<(), usize> {
    // Only copy from user address
    if !is_user(src..src + dst.len()) {
        return Err(dst.len());
    }

    let src = ptr::from_exposed_addr(src.virt);
    // Safety: Memory range is valid
    unsafe { copy_may_fault(src, dst.as_mut_ptr(), dst.len()) }
}

/// Copies data to userspace. Returns the number of remaining bytes on failure.
pub fn copy_to_user(dst: VirtAddr, src: &[u8]) -> Result<(), usize> {
    // Only copy to user address
    if !is_user(dst..dst + src.len()) {
        return Err(src.len());
    }

    let dst = ptr::from_exposed_addr_mut(dst.virt);
    // Safety: Memory range is valid
    unsafe { copy_may_fault(src.as_ptr(), dst, src.len()) }
}

/// Returns whether an address range belongs to userspace
#[allow(clippy::cast_possible_wrap)]
pub fn is_user(addr: Range<VirtAddr>) -> bool {
    addr.start <= addr.end && addr.end.virt as isize >= 0
}

/// Copies bytes while allowing user memory access and handling traps. Returns the number of
/// remaining bytes on failure.
unsafe fn copy_may_fault(src: *const u8, dst: *mut u8, mut cnt: usize) -> Result<(), usize> {
    interrupt::free(|| {
        // Temporarily enable user memory access. Safety: That's always safe.
        unsafe { csr::set!("sstatus", SSTATUS_SUM) };
        // Temporarily install `expected_trap_handler` as trap handler. Safety: It is a valid trap
        // handler and aligned to 4 bytes.
        let prev_handler = unsafe { csr::write!("stvec", expected_trap_handler) };

        // Copy each byte, check for access fault. Make sure only 4-byte instructions may fault.
        // Safety: This code is correct.
        unsafe {
            asm!(
                // Set `t0` to zero
                "mv t0, zero",
                // Skip loop if count is zero
                "beqz {cnt}, 2f",
                // Copy loop
                "1:",
                // Copy byte from source to destination, using 4-byte instructions
                ".option push",
                ".option norvc",
                "lb {tmp}, ({src})",
                "sb {tmp}, ({dst})",
                ".option pop",
                // Skip to end if `t0` got set
                "bnez t0, 2f",
                // Increment pointers and decrement count
                "addi {src}, {src}, 1",
                "addi {dst}, {dst}, 1",
                "addi {cnt}, {cnt}, -1",
                // Loop back up until count is zero
                "bnez {cnt}, 1b",
                "2:",
                src = inout(reg) src => _,
                dst = inout(reg) dst => _,
                cnt = inout(reg) cnt,
                tmp = out(reg) _,
                out("t0") _,
                options(preserves_flags, nostack),
            );
        }

        // Reinstall previous trap handler. Safety: It was valid previously.
        unsafe { csr::write!("stvec", prev_handler) };
        // Disable user memory access. Safety: That's always safe.
        unsafe { csr::clear!("sstatus", SSTATUS_SUM) };

        // Check for error and return
        if cnt == 0 {
            Ok(())
        } else {
            Err(cnt)
        }
    })
}

/// Handles traps while copying in [`copy_may_fault`]
#[repr(align(4))]
#[naked]
unsafe extern "C" fn expected_trap_handler() -> ! {
    // Skip over the faulting memory instruction (always 4 byte) and set `t0` to -1. Safety: The
    // active code is designed to handle this.
    unsafe {
        asm!(
            // Get faulting address
            "csrr t0, sepc",
            // Skip over it
            "addi t0, t0, 4",
            // Write it back
            "csrw sepc, t0",
            // Set `t0` to -1
            "li t0, -1",
            // Return from trap
            "sret",
            options(noreturn),
        );
    }
}
