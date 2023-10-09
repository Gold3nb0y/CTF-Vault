//! Parse a flattened device tree

use core::ops::Range;

use fdt::Fdt;
use next_gen::{generator, mk_gen};

use crate::{addr::PhysAddr, util::local_addr_of};

/// Yields all usable memory regions
#[generator(yield(Range<PhysAddr>))]
#[allow(clippy::doc_markdown)]
pub fn usable_memory(dtb: &Fdt<'_>) {
    // Iterate over all memory regions
    mk_gen!(let mems = memory(dtb));
    for mem in mems {
        // Track current range as start, mid, and end, where [start, mid) is usable and [mid, end)
        // is reserved
        let mut start = mem.start;

        while start < mem.end {
            let mut end = mem.end;
            let mut mid = end;

            // Scan reservations and update mid and end
            mk_gen!(let reservations = reservations(dtb));
            for res in reservations {
                if start < res.end && res.end < mid {
                    end = res.end;
                }
                if res.start <= end && end < res.end {
                    end = res.end;
                }

                if start < res.end && res.start <= mid {
                    mid = res.start.max(start);
                }
            }

            // Yield current range
            if start < mid {
                yield_!(PhysAddr::new(start)..PhysAddr::new(mid));
            }

            // Update start point for next range
            start = end;
        }
    }
}

/// Yields all reserved memory regions
#[generator(yield(Range<usize>))]
fn reservations(dtb: &Fdt<'_>) {
    // Get reservations from memory reservation block
    for res in dtb.memory_reservations() {
        let start = res.address().expose_addr();
        let end = start + res.size();
        assert!(
            start <= end,
            "Memory reservation block includes invalid range",
        );
        if start < end {
            yield_!(start..end);
        }
    }

    // Get reservations from special node, used e.g. by QEMU
    for node in dtb.find_all_nodes("/reserved-memory") {
        for mem in node.children() {
            if let Some(reg) = mem.reg() {
                for res in reg {
                    let start = res.starting_address.expose_addr();
                    let end = start + res.size.expect("reserved-memory region has no size");
                    assert!(start <= end, "reserved-memory includes invalid range");
                    if start < end {
                        yield_!(start..end);
                    }
                }
            }
        }
    }

    // Additionally reserve the kernel image
    yield_!(local_addr_of!(_kernel_start: usize)..local_addr_of!(_kernel_end: usize));
}

/// Yields all memory regions of the system
#[generator(yield(Range<usize>))]
fn memory(dtb: &Fdt<'_>) {
    // Get ranges from all memory nodes
    for mem in dtb.find_all_nodes("/memory") {
        if let Some(reg) = mem.reg() {
            for res in reg {
                let start = res.starting_address.expose_addr();
                let end = start + res.size.expect("memory region has no size");
                assert!(start <= end, "memory includes invalid range");
                if start < end {
                    yield_!(start..end);
                }
            }
        }
    }
}
