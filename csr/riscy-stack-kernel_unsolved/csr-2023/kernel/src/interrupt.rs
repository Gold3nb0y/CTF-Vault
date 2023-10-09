//! Managing whether interrupts are enabled or disabled

use core::sync::atomic::{compiler_fence, Ordering};

use crate::csr;

/// *Supervisor Interrupt Enable* bit of the *Supervisor Status Register* CSR
const SSTATUS_SIE: usize = 1 << 1;

/// Returns whether interrupts are enabled
#[must_use]
pub fn enabled() -> bool {
    // Safety: Reading `sstatus` is always safe
    let status = unsafe { csr::read!("sstatus") };
    status & SSTATUS_SIE != 0
}

/// Enables or disables interrupts and returns the previous state.
///
/// # Safety
///
/// Interrupts may always be disabled. Interrupts may only be enabled if no interrupt-free lock is
/// being held.
pub unsafe fn set_enabled(enable: bool) -> bool {
    let status = if enable {
        // Safety: Enabling interrupts is safe once the trap handler has been set up and when we
        // hold no interrupt-free lock
        unsafe { csr::set!("sstatus", SSTATUS_SIE) }
    } else {
        // Safety: Disabling interrupts is always safe
        unsafe { csr::clear!("sstatus", SSTATUS_SIE) }
    };
    status & SSTATUS_SIE != 0
}

/// Runs the given closure with interrupts disabled. Interrupts are restored to their previous state
/// upon return.
pub fn free<R>(func: impl FnOnce() -> R) -> R {
    let _guard = IntFreeGuard::new();
    func()
}

/// Interrupt-free drop guard. Disables interrupts until it goes out of scope.
#[must_use]
pub struct IntFreeGuard {
    /// Whether interrupts were enabled before
    enabled: bool,
}

impl IntFreeGuard {
    /// Disables interrupts and creates a drop guard that restores the previous interrupt state
    pub fn new() -> Self {
        // Disable interrupts. Safety: Disabling interrupts is always safe.
        let enabled = unsafe { set_enabled(false) };
        // Make sure no memory accesses inside the guard are moved before it
        compiler_fence(Ordering::Acquire);

        Self { enabled }
    }
}

impl Drop for IntFreeGuard {
    fn drop(&mut self) {
        // Make sure no memory accesses inside the guard are moved after it
        compiler_fence(Ordering::Release);
        // Restore interrupt status. Safety: We just restore it to its previous value.
        unsafe { set_enabled(self.enabled) };
    }
}
