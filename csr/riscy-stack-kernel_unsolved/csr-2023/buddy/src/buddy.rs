//! Buddy allocator

use core::{
    ops::{ControlFlow, Range},
    ptr::NonNull,
};

use crate::linked_list::{ListElement, ListHead};

/// Buddy allocator.
///
/// Const generic parameters:
///
/// - `BASE_SIZE`: Smallest allocatable block size
///
/// - `ORDERS`: Number of managed block orders
pub struct Buddy<const BASE_SIZE: usize, const ORDERS: usize> {
    /// Free-list of blocks by order
    blocks: [ListHead; ORDERS],
}

impl<const BASE_SIZE: usize, const ORDERS: usize> Buddy<BASE_SIZE, ORDERS> {
    /// Maximum size of a block
    pub const MAX_SIZE: usize = BASE_SIZE << (ORDERS - 1);

    /// Creates a new allocator without any blocks
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            blocks: [const { ListHead::new() }; ORDERS],
        }
    }

    /// Adds memory to this allocator.
    ///
    /// # Safety
    ///
    /// The provided range must be valid and point to a single allocation.
    pub unsafe fn add_memory(&mut self, mem: Range<NonNull<u8>>) {
        // Align range to base size
        let start = mem
            .start
            .as_ptr()
            .map_addr(|addr| addr.next_multiple_of(BASE_SIZE));
        let end = mem.end.as_ptr().map_addr(|addr| addr - addr % BASE_SIZE);

        // Iterate over largest possible blocks in the range
        let mut block = start;
        while block < end {
            // Determine maximum order of current block. Safety: `block` points before `end`
            let order_rem = (unsafe { end.sub_ptr(block) } / BASE_SIZE).ilog2() as usize;
            let order_align = (block.addr() / BASE_SIZE).trailing_zeros() as usize;
            let order = (ORDERS - 1).min(order_rem).min(order_align);

            // Add base block to free-list. Safety: `block` is a valid block of order `order`.
            unsafe { self.free(order, NonNull::new_unchecked(block)) };
            // Safety: `block` is a valid block of order `order`
            block = unsafe { block.add(BASE_SIZE << order) };
        }
    }

    /// Tries to allocate a block of the given order from this allocator.
    ///
    /// # Panics
    ///
    /// Panics when `order` is not less than `ORDERS`.
    pub fn try_alloc(&mut self, order: usize) -> Option<NonNull<u8>> {
        assert!(order < ORDERS);

        // Try to find block of requested order or higher
        for higher in order..ORDERS {
            // Remove found block from free-list
            if let Some(block) = self.blocks[higher].pop() {
                // Split block multiple times
                for cur_order in (order..higher).rev() {
                    // Get second subblock and add it to the free-list. Safety: `block` is of higher
                    // order, so we can split it.
                    unsafe {
                        let second =
                            NonNull::new_unchecked(block.as_ptr().byte_add(BASE_SIZE << cur_order));
                        self.blocks[cur_order].push(second);
                    }
                }

                // `block` is now of order `order`, all second subblocks up to this order have been
                // added to the free-list
                return Some(block.cast());
            }
        }

        None
    }

    /// Allocates a block of the given order from this allocator.
    ///
    /// # Panics
    ///
    /// Panics when the allocator is out of memory, or when `order` is not less than `ORDERS`.
    pub fn alloc(&mut self, order: usize) -> NonNull<u8> {
        self.try_alloc(order)
            .expect("Buddy allocator out of memory")
    }

    /// Frees a block back to this allocator.
    ///
    /// # Panics
    ///
    /// Panics when `order` is not less than `ORDERS`.
    ///
    /// # Safety
    ///
    /// Block has to have been allocated from this allocator with the given order.
    pub unsafe fn free(&mut self, order: usize, block: NonNull<u8>) {
        assert!(order < ORDERS);
        assert!(block.as_ptr().is_aligned_to(BASE_SIZE << order));
        let block = block.cast::<ListElement>();

        // Repeatedly try to merge the block with its buddy, if the buddy is free
        if order < ORDERS - 1 {
            // Determine buddy
            let buddy_addr = block.addr().get() ^ (BASE_SIZE << order);

            // Check if buddy is free
            let r = self.blocks[order].try_for_each_mut(|elem| {
                if elem.get().addr().get() == buddy_addr {
                    // Found buddy, remove it from the free-list
                    let buddy = elem.remove();
                    ControlFlow::Break(buddy)
                } else {
                    ControlFlow::Continue(())
                }
            });
            if let ControlFlow::Break(buddy) = r {
                let lower = block.min(buddy).cast();
                // Merge with buddy and recurse. Safety: `lower` is valid block of next order.
                unsafe { self.free(order + 1, lower) };
                return;
            }
        }

        // No buddy to merge with, just add to free-list. Safety: `block` is a valid block of order
        // `order`.
        unsafe { self.blocks[order].push(block) };
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::*;

    /// Tests the basic functionality of the buddy allocator
    #[test]
    fn test_buddy() {
        let mut mem = [0x41u8; 0x1000];
        let mem = mem.as_mut_ptr();

        let mut buddy = Buddy::<0x10, 5>::new();

        // Safety: Ranges are contained inside `mem`
        unsafe {
            buddy.add_memory(Range {
                start: NonNull::new_unchecked(mem),
                end:   NonNull::new_unchecked(mem.add(0x400)),
            });
            buddy.add_memory(Range {
                start: NonNull::new_unchecked(mem.add(0x800)),
                end:   NonNull::new_unchecked(mem.add(0xc00)),
            });
        }

        let mut blocks = Vec::new();
        for order in 0..=4 {
            blocks.push(buddy.alloc(order));
        }

        for (order, block) in blocks.into_iter().enumerate() {
            // Safety: Block was allocated with this order
            unsafe { buddy.free(order, block) };
        }
    }
}
