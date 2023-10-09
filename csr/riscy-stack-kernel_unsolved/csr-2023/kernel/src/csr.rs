//! Reading and writing CSRs

use core::arch::asm;

/// Reads from a CSR
pub macro read($id:literal) {
    {
        let out: usize;
        asm!(
            concat!("csrr {out}, ", $id),
            out = out(reg) out,
            options(nostack),
        );
        out
    }
}

/// Writes to a CSR and returns the old value. If `val` is less wide than `usize`, its upper bits
/// are undefined.
pub macro write($id:literal, $val:expr) {
    {
        let out: usize;
        asm!(
            concat!("csrrw {out}, ", $id, ", {val}"),
            out = lateout(reg) out,
            val = in(reg) $val,
            options(nostack),
        );
        out
    }
}

/// Sets bits in a CSR and returns the old value. If `val` is less wide than `usize`, its upper bits
/// are undefined.
pub macro set($id:literal, $val:expr) {
    {
        let out: usize;
        asm!(
            concat!("csrrs {out}, ", $id, ", {val}"),
            out = lateout(reg) out,
            val = in(reg) $val,
            options(nostack),
        );
        out
    }
}

/// Clears bits in a CSR and returns the old value. If `val` is less wide than `usize`, its upper
/// bits are undefined.
pub macro clear($id:literal, $val:expr) {
    {
        let out: usize;
        asm!(
            concat!("csrrc {out}, ", $id, ", {val}"),
            out = lateout(reg) out,
            val = in(reg) $val,
            options(nostack),
        );
        out
    }
}
