//! Various utilities

use core::{arch::asm, ops::Range};

/// Extracts bits from an integer value
pub macro bits {
    ($val:ident[$high:literal : $low:literal]) => {
        ($val >> $low) & ((1 << ($high - $low + 1)) - 1)
    },
    ($val:ident[$count:literal @ $base:literal]) => {
        ($val >> $base) & ((1 << $count) - 1)
    },
}

/// Gets address of a symbol, without requiring a GOT entry
pub macro local_addr_of($sym:ident : $ty:ty) {
    {
        let sym: $ty;
        // Safety: Using `lla` is safe and an undefined symbol will trigger a linker error
        unsafe {
            asm!(
                concat!("lla {sym}, ", stringify!($sym)),
                sym = out(reg) sym,
                options(pure, nomem, nostack, preserves_flags),
            );
        }
        sym
    }
}

/// Maps a function over a range by applying it to both bounds
pub fn map_range<T, R>(range: Range<T>, mut fun: impl FnMut(T) -> R) -> Range<R> {
    fun(range.start)..fun(range.end)
}
