//! Manage virtual memory.
//!
//! We use Sv39 with 39-bit virtual addresses; the VA hole is from `0x40_00000000` to
//! `0xffff_ffc0_0000_0000`.
//!
//! The virtual address space is allocated as follows:
//!
//! - `0x0` -- `0x40_0000_0000`: Available to userspace
//!
//! - `0xffff_ffc0_0000_0000` -- `0xffff_ffe0_0000_0000`: Physmap
//!   - Contiguous mapping of the first 128 GiB of physical memory
//!   - Uses gigapages
//!   - Completely `rw-`
//!   - Subset of pages managed by buddy page allocator
//!
//! - `0xffff_ffe0_0000_0000`: Kernel image
//!   - Uses 4 KB pages, correct protections for each segment
//!
//! - `0xffff_ffe1_0000_0000`: Stacks for kernel threads, two per hart
//!   - Surrounded by guard pages
//!   - One normal stack and one interrupt stack per hart
//!
//! During boot we temporarily set up an identity mapping of the kernel, at whichever address it was
//! loaded at by the previous boot stage. This mapping is only needed to transition to virtual
//! addresses and removed when we are done bootstrapping.

use core::{
    arch::asm,
    ops::Range,
    ptr::{self, NonNull},
};

use buddy::Buddy;
use fdt::Fdt;
use next_gen::mk_gen;

use crate::{
    addr::{PhysAddr, VirtAddr},
    boot, csr,
    dtb::usable_memory,
    page_table::{PageAttributes, RootPageTable},
    print::println,
    util::{local_addr_of, map_range},
};

/// Buddy page allocator, allocates from page-sized blocks up to 64 MiB blocks
type PageBuddy = Buddy<PAGE, 15>;

/// Size of a page (4 kiB)
pub const PAGE: usize = 1 << 12;
// /// Size of a megapage (2 MiB)
// const MEGAPAGE: usize = 1 << 21;
/// Size of a gigapage (1 GiB)
pub const GIGAPAGE: usize = 1 << 30;

/// Virtual physmap base address
pub const PHYSMAP_BASE: VirtAddr = VirtAddr::new(0xffff_ffc0_0000_0000);
/// Physmap size (128 GiB)
pub const PHYSMAP_SIZE: usize = 1 << 37;
/// Physmap range
pub const PHYSMAP: Range<VirtAddr> = PHYSMAP_BASE..PHYSMAP_BASE + PHYSMAP_SIZE;

/// Virtual kernel image base address
pub const KERNEL_BASE: VirtAddr = VirtAddr::new(0xffff_ffe0_0000_0000);

/// Virtual kernel stack base address
pub const STACK_BASE: VirtAddr = VirtAddr::new(0xffff_ffe1_0000_0000);
/// Kernel stack order
pub const STACK_ORDER: usize = 4;
/// Kernel stack size
pub const STACK_SIZE: usize = PAGE << STACK_ORDER;
/// Kernel stack range
pub const STACK: Range<VirtAddr> = STACK_BASE..STACK_BASE + STACK_SIZE;

/// Virtual interrupt stack base address
pub const INT_STACK_BASE: VirtAddr = STACK_BASE + STACK_SIZE + PAGE;
/// Interrupt stack order
pub const INT_STACK_ORDER: usize = 0;
/// Interrupt stack size
pub const INT_STACK_SIZE: usize = PAGE << INT_STACK_ORDER;
/// Interrupt stack range
pub const INT_STACK: Range<VirtAddr> = INT_STACK_BASE..INT_STACK_BASE + INT_STACK_SIZE;

/// Global page allocator
pub static mut ALLOC: PageBuddy = PageBuddy::new();

/// Root (level 2) page table that only includes the kernel space mappings
pub static mut KERNEL_PT: RootPageTable = RootPageTable::empty();

/// Initializes virtual memory system and page allocator, relocates kernel image and stack, and
/// switches to using virtual addresses.
///
/// # Safety
///
/// May only be called once during startup.
pub unsafe fn init(dtb: *const u8) -> ! {
    println!("Initializing virtual memory");

    // Grab reference of page table. Safety: We are the only thread
    let pt = unsafe { &mut KERNEL_PT };

    // Identity-map kernel so we can keep executing from here. This is done with one or more
    // gigapages (1 GB each), so that we don't need to allocate any more page tables.
    let id_start = VirtAddr::new(local_addr_of!(_kernel_start: usize) & !(GIGAPAGE - 1));
    let id_end = VirtAddr::new(local_addr_of!(_kernel_end: usize).next_multiple_of(GIGAPAGE));
    let id_map = id_start..id_end;
    for addr in id_map.clone().step_by(GIGAPAGE) {
        pt.map_gigapage(PhysAddr::new(addr.virt), addr, PageAttributes::rwx());
    }
    println!("  Kernel ID       @ {id_map:?}");

    // Set up physmap: Map all physical memory using gigapages
    for addr in PHYSMAP.step_by(GIGAPAGE) {
        pt.map_gigapage(addr.phys(), addr, PageAttributes::rw().global());
    }
    println!("  Physmap         @ {PHYSMAP:?}",);

    // Switch to virtual memory. Safety: The page table is valid
    unsafe { set_satp(PhysAddr::new((pt as *const RootPageTable).addr()), 0) };

    // Initialize page allocator. Safety: The firmware provides a valid DTB.
    unsafe { init_buddy(dtb) };

    // Set up actual kernel mappings
    let kernel_phys_start = local_addr_of!(_kernel_start: usize);
    /// Maps a range of the kernel image with some protection
    macro map_kernel($start:ident, $end:ident, $attr:ident) {
        let phys_start = local_addr_of!($start: usize);
        let phys_end = local_addr_of!($end: usize).next_multiple_of(PAGE);
        let virt_start = KERNEL_BASE + (phys_start - kernel_phys_start);
        let virt_end = virt_start + (phys_end - phys_start);
        let virt = virt_start..virt_end;
        println!(
            concat!("  Kernel image ", stringify!($attr), " @ {:?}"),
            virt,
        );
        pt.map_page_range(
            PhysAddr::new(phys_start),
            virt,
            PageAttributes::$attr().global(),
        );
    }
    map_kernel!(_seg_rx_start, _seg_rx_end, rx);
    map_kernel!(_seg_r_start, _seg_r_end, ro);
    map_kernel!(_seg_rw_start, _seg_rw_end, rw);

    // Allocate kernel stack. Safety: We are the only thread
    let stack = unsafe { ALLOC.alloc(STACK_ORDER) };
    // Map kernel stack into the correct place
    pt.map_page_range(
        VirtAddr::new(stack.addr().get()).phys(),
        STACK,
        PageAttributes::rw().global(),
    );
    println!("  Kernel stack    @ {STACK:?}");

    // Switch to actual kernel mappings and new kernel stack
    let old_stack_start = local_addr_of!(_stack_start: usize);
    let old_stack_end = local_addr_of!(_stack_end: usize);
    let part2 = KERNEL_BASE.virt + ((init_part2 as usize) - kernel_phys_start);
    // Safety: We respect ABI when calling into rust
    unsafe {
        asm!(
            // Set up the new stack
            "li sp, {stack}",
            // Call into rust at the new mappings
            "jr {rs}",
            stack = const STACK.end.virt,
            rs = in(reg) part2,
            in("a0") old_stack_start,
            in("a1") old_stack_end,
            in("a2") id_start.virt,
            in("a3") id_end.virt,
            options(noreturn),
        );
    }
}

/// Second part of the initialization, removes old mappings and calls back to [`boot`]
unsafe extern "C" fn init_part2(
    old_stack_start: PhysAddr,
    old_stack_end: PhysAddr,
    id_start: VirtAddr,
    id_end: VirtAddr,
) -> ! {
    // Put ranges together
    let old_stack = old_stack_start..old_stack_end;
    let id_map = id_start..id_end;

    // Grab reference of page table. Safety: We are the only thread
    let pt = unsafe { &mut KERNEL_PT };

    // Add old kernel stack to page allocator
    println!("  Old stack       @ {old_stack:?}");
    // Safety: Old kernel stack is no longer in use, and we are the only thread
    unsafe { ALLOC.add_memory(map_range(old_stack, |x| virt_to_ptr(x.physmap()))) };

    // Allocate interrupt stack. Safety: We are the only thread.
    let int = unsafe { ALLOC.alloc(INT_STACK_ORDER) };
    // Map interrupt stack into the correct place
    pt.map_page_range(
        VirtAddr::new(int.addr().get()).phys(),
        INT_STACK,
        PageAttributes::rw().global(),
    );
    println!("  Interrupt stack @ {INT_STACK:?}");

    // Remove temporary kernel ID mapping
    println!("Removing kernel ID mapping {id_map:?}");
    for addr in id_map.step_by(GIGAPAGE) {
        // Safety: We are the only thread
        pt.unmap_gigapage(addr);
    }
    // After the kernel ID mapping is removed, don't do anything that requires relocations before
    // applying them again

    // Call back to boot module. Safety: Only called on startup
    unsafe { boot::post_vm_entry(INT_STACK.end) };
}

/// Set the currently active page table and address-space. For changes to actually be visible,
/// executing an `sfence.vma` might be necessary.
///
/// # Safety
///
/// `pt` must be the address of a valid page table.
unsafe fn set_satp(pt: PhysAddr, asid: u16) {
    // Page table must be aligned to page size
    assert!(pt.phys % PAGE == 0);

    let satp = (8 << 60) | ((asid as usize) << 44) | pt.ppn();
    // Safety: The page table is valid
    unsafe { csr::write!("satp", satp) };
}

/// Initializes the buddy page allocator.
///
/// # Safety
///
/// May only be called once during boot, and the DTB must be valid.
#[allow(clippy::doc_markdown)]
unsafe fn init_buddy(dtb: *const u8) {
    // Safety: The firmware provides a valid DTB
    let dtb = unsafe { Fdt::from_ptr(dtb) }.expect("Invalid DTB");

    // Iterate over all usable memory regions
    mk_gen!(let mems = usable_memory(&dtb));
    for mem in mems {
        // Map range to physmap
        let mem = map_range(mem, PhysAddr::physmap);
        println!("  Usable memory   @ {mem:?}");
        // Add memory region to allocator. Safety: Memory region was provided as usable by the
        // firmware, and we are the only thread.
        unsafe { ALLOC.add_memory(map_range(mem, virt_to_ptr)) };
    }
}

/// Returns a pointer to the given virtual address
fn virt_to_ptr(virt: VirtAddr) -> NonNull<u8> {
    NonNull::new(ptr::from_exposed_addr_mut(virt.virt)).expect("Pointer is null")
}
