//! Syscall handling

use core::{
    ptr::{self, NonNull},
    result,
};

use crate::{
    addr::VirtAddr,
    boot::halt,
    console::Console,
    page_table::PageAttributes,
    print::println,
    trap::TrapFrame,
    usermode::{copy_from_user, copy_to_user, is_user},
    vm::{ALLOC, KERNEL_PT, PAGE},
};

/// Result of a system call
pub type Result<T> = result::Result<T, Error>;

/// Errors that can occur during a system call
#[derive(Debug)]
#[repr(usize)]
pub enum Error {
    /// Invalid argument value, `EINVAL`
    InvalidValue = 1,
    /// Unmapped or kernel-space address, `EFAULT`
    AddressFault,
    /// System has no more memory, `ENOMEM`
    OutOfMemory,
    /// Invalid system call number, `ENOSYS`
    InvalidSyscall,
}

/// Handles a system call
pub fn handle(frame: &mut TrapFrame) {
    // Arguments in a0.., syscall number in a7
    let num = frame.regs.regs_gp[16];
    let arg1 = frame.regs.regs_gp[9];
    let arg2 = frame.regs.regs_gp[10];
    let arg3 = frame.regs.regs_gp[11];

    // Invoke syscall
    let res = match num {
        0 => exit(),
        1 => read(VirtAddr::new(arg1), arg2),
        2 => write(VirtAddr::new(arg1), arg2),
        3 => map(VirtAddr::new(arg1), arg2, arg3).map(|_| 0),
        4 => unmap(VirtAddr::new(arg1), arg2).map(|_| 0),
        0x1337 => {
            print_flag();
            Ok(0)
        }
        _ => Err(Error::InvalidSyscall),
    };

    // Write back result
    let (val, err) = match res {
        Ok(val) => (val, 0),
        Err(err) => (0, err as usize),
    };
    frame.regs.regs_gp[9] = val;
    frame.regs.regs_gp[10] = err;

    // Skip over `ecall` instruction
    frame.epc += 4;
}

/// Exits the program
fn exit() -> ! {
    println!("\n\nUserspace requested halt");
    halt();
}

/// Reads input from the console
fn read(buf: VirtAddr, size: usize) -> Result<usize> {
    // Use stack buffer to reduce number of copies
    let mut stack_buf = [0u8; 0x100];
    for addr in (buf..buf + size).step_by(stack_buf.len()) {
        let len = stack_buf.len().min(buf + size - addr);

        // Read from console, copy to user
        Console.read_exact(&mut stack_buf[..len]);
        copy_to_user(addr, &stack_buf[..len]).map_err(|_| Error::AddressFault)?;
    }

    Ok(size)
}

/// Writes output to the console
fn write(buf: VirtAddr, size: usize) -> Result<usize> {
    // Use stack buffer to reduce number of copies
    let mut stack_buf = [0u8; 0x100];
    for addr in (buf..buf + size).step_by(stack_buf.len()) {
        let len = stack_buf.len().min(buf + size - addr);

        // Copy from user, write to console
        copy_from_user(addr, &mut stack_buf[..len]).map_err(|_| Error::AddressFault)?;
        Console.write_bytes(&stack_buf[..len]);
    }

    Ok(size)
}

/// Maps memory into the process
pub fn map(addr: VirtAddr, size: usize, prot: usize) -> Result<()> {
    // Must be a userspace address range
    if !is_user(addr..addr + size) {
        return Err(Error::AddressFault);
    }

    // Range must be page-aligned
    if addr.page_offset() != 0 || size % PAGE != 0 {
        return Err(Error::InvalidValue);
    }

    // Parse protection value
    let attr = match prot {
        1 => PageAttributes::ro(),
        3 => PageAttributes::rw(),
        4 => PageAttributes::xo(),
        5 => PageAttributes::rx(),
        7 => PageAttributes::rwx(),
        _ => return Err(Error::InvalidValue),
    }
    .user();

    // Iterate over pages, allocate and map them
    for addr in (addr..addr + size).step_by(PAGE) {
        // Allocate page. Safety: We are the only thread.
        let page = unsafe { ALLOC.try_alloc(0) }.ok_or(Error::OutOfMemory)?;
        // Zero page. Safety: Page was just allocated.
        unsafe { ptr::write_bytes::<u8>(page.as_ptr(), 0, PAGE) };
        let page = VirtAddr::new(page.as_ptr().expose_addr());
        // Map into userspace. Safety: We are the only thread.
        unsafe { KERNEL_PT.map_page(page.phys(), addr, attr) };
    }

    Ok(())
}

/// Unmaps memory from the process
fn unmap(addr: VirtAddr, size: usize) -> Result<()> {
    // Must be a userspace address range
    if !is_user(addr..addr + size) {
        return Err(Error::AddressFault);
    }

    // Range must be page-aligned
    if addr.page_offset() != 0 || size % PAGE != 0 {
        return Err(Error::InvalidValue);
    }

    // Iterate over pages, unmap and free them
    for addr in (addr..addr + size).step_by(PAGE) {
        // Unmap page. Safety: We are the only thread.
        let page = unsafe { KERNEL_PT.unmap_page(addr) };
        let page = NonNull::new(ptr::from_exposed_addr_mut(page.physmap().virt)).unwrap();
        // Free page. Safety: Page was allocated of order zero and we are the only thread.
        unsafe { ALLOC.free(0, page) };
    }

    Ok(())
}

/// Output the flag of the first stage
fn print_flag() {
    println!("Flag for first stage: CSR{{user_XXXXXXXXXXXXXX}}");
}
