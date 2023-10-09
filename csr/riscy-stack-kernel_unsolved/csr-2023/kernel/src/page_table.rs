//! Managing page tables

#![allow(clippy::module_name_repetitions)]

use core::{ops::Range, ptr};

use bitfield::bitfield;

use crate::{
    addr::{PhysAddr, VirtAddr},
    vm::{ALLOC, GIGAPAGE, PAGE},
};

/// Attributes of a page or superpage
#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
pub struct PageAttributes {
    /// Read permission
    pub readable:   bool,
    /// Write permission
    pub writable:   bool,
    /// Execute permission
    pub executable: bool,
    /// User or kernel page
    pub user:       bool,
    /// Mapping present in all address-spaces
    pub global:     bool,
}

impl PageAttributes {
    /// Read-only
    pub const fn ro() -> Self {
        Self {
            readable:   true,
            writable:   false,
            executable: false,
            user:       false,
            global:     false,
        }
    }

    /// Read-write
    pub const fn rw() -> Self {
        Self {
            readable:   true,
            writable:   true,
            executable: false,
            user:       false,
            global:     false,
        }
    }

    /// Read-execute
    pub const fn rx() -> Self {
        Self {
            readable:   true,
            writable:   false,
            executable: true,
            user:       false,
            global:     false,
        }
    }

    /// Read-write-execute
    pub const fn rwx() -> Self {
        Self {
            readable:   true,
            writable:   true,
            executable: true,
            user:       false,
            global:     false,
        }
    }

    /// Execute-only
    pub const fn xo() -> Self {
        Self {
            readable:   false,
            writable:   false,
            executable: true,
            user:       false,
            global:     false,
        }
    }

    /// Marks page as user-accessible
    pub fn user(mut self) -> Self {
        self.user = true;
        self
    }

    /// Marks page as global
    pub fn global(mut self) -> Self {
        self.global = true;
        self
    }
}

bitfield! {
    /// Entry in a page table of any level
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct PageTableEntry(u64);
    impl Debug;
    pub valid, set_valid: 0;
    pub readable, set_readable: 1;
    pub writable, set_writable: 2;
    pub executable, set_executable: 3;
    pub user, set_user: 4;
    pub global, set_global: 5;
    pub accessed, set_accessed: 6;
    pub dirty, set_dirty: 7;
    pub reserved, set_reserved: 9, 8;
    pub ppn, set_ppn: 53, 10;
}

impl PageTableEntry {
    /// Creates an invalid page table entry, that does not map anything
    pub const fn new_invalid() -> Self {
        Self(0)
    }

    /// Creates a page table entry referring to the next-level page table at the given physical
    /// address
    pub fn new_next(phys: PhysAddr) -> Self {
        assert!(phys.page_offset() == 0);
        let mut entry = Self(0);
        entry.set_valid(true);
        entry.set_ppn(phys.ppn() as u64);
        entry
    }

    /// Creates a leaf page table entry mapping to the given physical address with the given
    /// attributes
    pub fn new_leaf(phys: PhysAddr, attr: PageAttributes) -> Self {
        assert!(phys.page_offset() == 0);
        let mut entry = Self(0);
        entry.set_valid(true);
        entry.set_readable(attr.readable);
        entry.set_writable(attr.writable);
        entry.set_executable(attr.executable);
        entry.set_user(attr.user);
        entry.set_global(attr.global);
        entry.set_ppn(phys.ppn() as u64);
        entry
    }

    /// Returns the physical address contained in this entry
    pub fn addr(self) -> PhysAddr {
        #[allow(clippy::cast_possible_truncation)]
        PhysAddr::from_ppn(self.ppn() as usize)
    }

    /// Returns whether this entry is a leaf
    pub fn leaf(self) -> bool {
        self.valid() && (self.readable() || self.writable() || self.executable())
    }

    /// Returns the address of the next-level page table referenced by this entry
    pub fn next(self) -> Option<PhysAddr> {
        (self.valid() && !self.leaf()).then(|| self.addr())
    }

    /// Replaces this entry's value using a volatile write
    pub fn replace(&mut self, val: Self) {
        // Safety: Pointer derived from self is valid
        unsafe { (self as *mut Self).write_volatile(val) };
    }
}

/// Page table for any level, exactly one page in size
#[repr(C, align(0x1000))]
pub struct PageTable {
    /// Page table entries
    pub entries: [PageTableEntry; 512],
}

impl PageTable {
    /// Creates an empty page table, that contains no valid mappings
    pub const fn empty() -> Self {
        Self {
            entries: [PageTableEntry(0); _],
        }
    }
}

/// Root (level 2) page table
#[repr(transparent)]
pub struct RootPageTable {
    /// Page table
    pub table: PageTable,
}

impl RootPageTable {
    /// Creates an empty page table, that contains no valid mappings
    pub const fn empty() -> Self {
        Self {
            table: PageTable::empty(),
        }
    }

    /// Maps a physical to a virtual address using a gigapage
    pub fn map_gigapage(&mut self, phys: PhysAddr, virt: VirtAddr, attr: PageAttributes) {
        // Page must be aligned to its size
        assert!(phys.phys % GIGAPAGE == 0);
        assert!(virt.virt % GIGAPAGE == 0);

        // Look up entry in the root page table and populate it
        let entry = &mut self.table.entries[virt.table_index(2)];
        assert!(!entry.valid(), "Page table entry is already present");
        entry.replace(PageTableEntry::new_leaf(phys, attr));
    }

    /// Unmaps the gigapage given by a virtual address. Returns its physical address.
    pub fn unmap_gigapage(&mut self, virt: VirtAddr) -> PhysAddr {
        // Page must be aligned to its size
        assert!(virt.virt % GIGAPAGE == 0);

        // Look up entry in the root page table and clear it
        let entry = &mut self.table.entries[virt.table_index(2)];
        assert!(entry.leaf(), "Page table entry is not mapped");
        let addr = entry.addr();
        entry.replace(PageTableEntry::new_invalid());
        addr
    }

    /// Maps a physical to a virtual address using a normal page
    pub fn map_page(&mut self, phys: PhysAddr, virt: VirtAddr, attr: PageAttributes) {
        // Page must be aligned to its size
        assert!(phys.page_offset() == 0);
        assert!(virt.page_offset() == 0);

        // Walk page table hierarchy to find entry and populate it
        let entry = self.walk_create(virt);
        assert!(!entry.valid(), "Page table entry is already present");
        entry.replace(PageTableEntry::new_leaf(phys, attr));
    }

    /// Maps a range of physical to virtual addresses using normal pages
    pub fn map_page_range(&mut self, phys: PhysAddr, virt: Range<VirtAddr>, attr: PageAttributes) {
        // Range must be aligned to page size
        assert!(phys.page_offset() == 0);
        assert!(virt.start.page_offset() == 0 && virt.end.page_offset() == 0);

        // Iterate over range and map each page
        let start = virt.start;
        for v in virt.step_by(PAGE) {
            self.map_page(phys + (v - start), v, attr);
        }
    }

    /// Unmaps the normal page given by a virtual address. Returns its physical address.
    pub fn unmap_page(&mut self, virt: VirtAddr) -> PhysAddr {
        // Page must be aligned to its size
        assert!(virt.page_offset() == 0);

        // Walk page table hierarchy to find entry and clear it
        let entry = self.walk_create(virt);
        assert!(entry.leaf(), "Page table entry is not mapped");
        let addr = entry.addr();
        entry.replace(PageTableEntry::new_invalid());
        addr
    }

    /// Unmaps the given virtual address range
    pub fn unmap_page_range(&mut self, virt: Range<VirtAddr>) {
        // Range must be aligned to page size
        assert!(virt.start.page_offset() == 0 && virt.end.page_offset() == 0);

        // Iterate over range and unmap each page
        for v in virt.step_by(PAGE) {
            self.unmap_page(v);
        }
    }

    /// Walks to the last (level 0) page table entry corresponding to the given virtual address.
    /// Creates any encountered nonexistent page tables.
    fn walk_create(&mut self, virt: VirtAddr) -> &mut PageTableEntry {
        // Start at root page table
        let mut table = &mut self.table;

        // Get next-level page tables
        for lvl in [2, 1] {
            // Get page table entry
            let entry = &mut table.entries[virt.table_index(lvl)];
            assert!(
                !entry.leaf(),
                "Page table entry is mapped as part of a superpage"
            );

            // Check if we have to allocate a new page table
            if let Some(next) = entry.next() {
                // Use the existing page table. Safety: Next-level page table is valid
                table = unsafe { &mut *ptr::from_exposed_addr_mut(next.physmap().virt) };
            } else {
                // Allocate a new page table. Safety: We are the only thread.
                let t = unsafe { ALLOC.alloc(0) }.cast::<PageTable>();
                // Initialize page table. Safety: We just received the pointer from the allocator.
                table = unsafe { t.as_uninit_mut() }.write(PageTable::empty());
                // Put new page table into the current entry
                assert!(!entry.valid());
                entry.replace(PageTableEntry::new_next(
                    VirtAddr::new((table as *mut PageTable).expose_addr()).phys(),
                ));
            }
        }

        // Get entry of level 0 page table
        &mut table.entries[virt.table_index(0)]
    }
}
