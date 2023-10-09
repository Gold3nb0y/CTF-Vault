//! Wrappers for virtual and physical addresses

#![allow(clippy::module_name_repetitions)]

use core::{
    fmt,
    iter::Step,
    ops::{Add, AddAssign, Sub, SubAssign},
};

use crate::{
    util::bits,
    vm::{PAGE, PHYSMAP_BASE, PHYSMAP_SIZE},
};

/// Virtual address
#[derive_const(PartialEq, PartialOrd)]
#[derive(Clone, Copy, Eq, Ord)]
#[repr(transparent)]
pub struct VirtAddr {
    /// Virtual address
    pub virt: usize,
}

impl VirtAddr {
    /// Wraps a given virtual address
    pub const fn new(virt: usize) -> Self {
        Self { virt }
    }

    /// Returns the page offset of this address
    pub const fn page_offset(self) -> usize {
        self.virt % PAGE
    }

    /// Returns the part of the virtual page number used to index into the given level of page
    /// tables
    pub const fn table_index(self, level: usize) -> usize {
        let virt = self.virt;
        match level {
            0 => bits!(virt[9 @ 12]),
            1 => bits!(virt[9 @ 21]),
            2 => bits!(virt[9 @ 30]),
            _ => panic!("Invalid page table level"),
        }
    }

    /// Returns the physical address of this virtual physmap address.
    ///
    /// # Panics
    ///
    /// Panics when this address is not in the physmap.
    pub const fn phys(self) -> PhysAddr {
        assert!(PHYSMAP_BASE <= self && self < PHYSMAP_BASE + PHYSMAP_SIZE);
        PhysAddr::new(self - PHYSMAP_BASE)
    }
}

/// Physical address
#[derive_const(PartialEq, PartialOrd)]
#[derive(Clone, Copy, Eq, Ord)]
#[repr(transparent)]
pub struct PhysAddr {
    /// Physical address
    pub phys: usize,
}

impl PhysAddr {
    /// Wraps a given physical address
    pub const fn new(phys: usize) -> Self {
        Self { phys }
    }

    /// Creates a physical address based on a physical page number
    pub const fn from_ppn(ppn: usize) -> Self {
        Self::new(ppn * PAGE)
    }

    /// Returns the physical page number of this address
    pub const fn ppn(self) -> usize {
        self.phys / PAGE
    }

    /// Returns the page offset of this address
    pub const fn page_offset(self) -> usize {
        self.phys % PAGE
    }

    /// Returns the virtual address in the physmap corresponding to this address
    pub const fn physmap(self) -> VirtAddr {
        assert!(self.phys < PHYSMAP_SIZE);
        PHYSMAP_BASE + self.phys
    }
}

/// Implements common traits on the address structs
macro impl_addr($ty:ident, $field:ident, $mark:ident) {
    impl const Add<usize> for $ty {
        type Output = Self;

        fn add(self, rhs: usize) -> Self::Output {
            Self::new(self.$field + rhs)
        }
    }

    impl const Sub<usize> for $ty {
        type Output = Self;

        fn sub(self, rhs: usize) -> Self::Output {
            Self::new(self.$field - rhs)
        }
    }

    impl const Sub for $ty {
        type Output = usize;

        fn sub(self, rhs: Self) -> Self::Output {
            self.$field - rhs.$field
        }
    }

    impl AddAssign<usize> for $ty {
        fn add_assign(&mut self, rhs: usize) {
            self.$field += rhs;
        }
    }

    impl SubAssign<usize> for $ty {
        fn sub_assign(&mut self, rhs: usize) {
            self.$field -= rhs;
        }
    }

    impl Step for $ty {
        fn steps_between(start: &Self, end: &Self) -> Option<usize> {
            Some(*end - *start)
        }

        fn forward_checked(start: Self, count: usize) -> Option<Self> {
            Some(start + count)
        }

        fn backward_checked(start: Self, count: usize) -> Option<Self> {
            Some(start - count)
        }
    }

    impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, concat!("0", stringify!($mark), "{:x}"), self.$field)
        }
    }

    impl fmt::Display for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(self, f)
        }
    }
}

impl_addr!(VirtAddr, virt, v);
impl_addr!(PhysAddr, phys, p);
