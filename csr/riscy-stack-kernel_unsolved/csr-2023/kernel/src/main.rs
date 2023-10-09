//! RISC-V kernel

#![no_std]
#![no_main]
#![feature(asm_const)]
#![feature(const_cmp)]
#![feature(const_trait_impl)]
#![feature(decl_macro)]
#![feature(derive_const)]
#![feature(fn_align)]
#![feature(format_args_nl)]
#![feature(generic_arg_infer)]
#![feature(inline_const)]
#![feature(int_roundings)]
#![feature(naked_functions)]
#![feature(panic_info_message)]
#![feature(ptr_as_uninit)]
#![feature(ptr_sub_ptr)]
#![feature(slice_from_ptr_range)]
#![feature(step_trait)]
#![feature(strict_provenance)]
#![warn(clippy::missing_docs_in_private_items)]
#![warn(clippy::pedantic)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

mod addr;
mod boot;
mod console;
mod csr;
mod dtb;
mod interrupt;
mod page_table;
mod panic;
mod print;
mod syscall;
mod trap;
mod usermode;
mod util;
mod vm;

use crate::{addr::VirtAddr, print::println, vm::PAGE};

/// Main entrypoint of the kernel, invoked after the runtime was initialized
fn main() {
    // Keep the flag of the second stage here. Safety: Pointer is valid
    unsafe { "CSR{kern_YYYYYYYYYYYYYY}".as_ptr().read_volatile() };

    // Initialize userspace. Safety: We are done booting.
    unsafe { usermode::init() };

    #[cfg(not(feature = "replace-kernel"))]
    run_userspace();
    #[cfg(feature = "replace-kernel")]
    run_shellcode();
}

/// Run userspace program
#[cfg(not(feature = "replace-kernel"))]
fn run_userspace() {
    // Get blob to place in userspace
    let blob = {
        #[cfg(not(feature = "replace-userspace"))]
        {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../target/userspace.bin"
            ))
        }
        #[cfg(feature = "replace-userspace")]
        {
            static mut BUF: [u8; 0x1000] = [0; _];
            let buf = unsafe { &mut BUF };
            println!("Send your code for userspace:");
            console::Console.read_exact(buf);
            buf
        }
    };

    // Allocate and map userspace memory
    let user_addr = VirtAddr::new(0x0800_0000);
    println!("Loading userspace {:?}", user_addr..user_addr + blob.len());
    syscall::map(user_addr, blob.len().next_multiple_of(PAGE), 7).unwrap();
    // Load userspace program
    usermode::copy_to_user(user_addr, blob).unwrap();
    println!("Switching to userspace\n\n");
    // Trigger transition into user mode. Safety: Trap handler will take over
    unsafe {
        core::arch::asm!("sd zero, 0x123(zero)", in("a0") user_addr.virt);
    }
}

/// Run shellcode in kernel mode
#[cfg(feature = "replace-kernel")]
fn run_shellcode() {
    use core::{ptr, slice};

    use crate::{
        page_table::PageAttributes,
        vm::{ALLOC, KERNEL_PT},
    };

    // Allocate page
    let page = unsafe { ALLOC.try_alloc(0) }.unwrap();
    let page = VirtAddr::new(page.as_ptr().expose_addr());
    // Map as rwx
    let addr = VirtAddr::new(0xffff_ffe2_0000_0000);
    unsafe { KERNEL_PT.map_page(page.phys(), addr, PageAttributes::rwx()) };

    println!("Send your code for the kernel:");
    console::Console.read_exact(unsafe {
        slice::from_raw_parts_mut(ptr::from_exposed_addr_mut(addr.virt), PAGE)
    });

    // Jump to shellcode
    unsafe {
        let sc = core::mem::transmute::<usize, unsafe extern "C" fn() -> !>(addr.virt);
        sc();
    }
}
