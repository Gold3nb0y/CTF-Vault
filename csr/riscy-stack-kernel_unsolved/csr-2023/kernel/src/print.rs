//! Macros for printing to the console

use core::{
    fmt::{Arguments, Write},
    format_args, format_args_nl,
};

use crate::console::Console;

/// Prints formatted arguments to the console
#[doc(hidden)]
pub fn _print(args: Arguments) {
    Console.write_fmt(args).unwrap();
}

/// Prints to the console
pub macro print($($arg:tt)*) {
    _print(format_args!($($arg)*))
}

/// Prints to the console, with newline
pub macro println {
    () => {
        print!("\n")
    },
    ($($arg:tt)*) => (
        _print(format_args_nl!($($arg)*))
    ),
}
