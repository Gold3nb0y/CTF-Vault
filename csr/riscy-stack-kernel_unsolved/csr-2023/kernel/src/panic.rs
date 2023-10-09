//! Panic handler

use core::{fmt::Write, panic::PanicInfo};

use crate::{boot::halt, console::Console, print::println};

/// Handles panics, by printing a message and looping
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        println!(
            "Panic occurred in file '{}' at line {}:",
            location.file(),
            location.line(),
        );
    } else {
        println!("Panic occurred:");
    }

    if let Some(&args) = info.message() {
        Console.write_fmt(args).unwrap();
    }
    println!();

    halt();
}
