//! Interface to the SBI console

use core::{arch::asm, fmt};

/// Interface to the SBI console
pub struct Console;

impl Console {
    /// Writes multiple bytes to the console
    pub fn write_bytes(&mut self, data: &[u8]) {
        for b in data {
            self.write_byte(*b);
        }
    }

    /// Writes a byte to the console
    #[allow(clippy::unused_self)]
    pub fn write_byte(&mut self, data: u8) {
        sbi_console_putchar(data);
    }

    /// Completely fills `buf` with bytes read from the console
    pub fn read_exact(&mut self, buf: &mut [u8]) {
        buf.fill_with(|| self.read_byte());
    }

    /// Reads a byte from the console
    #[allow(clippy::unused_self)]
    pub fn read_byte(&mut self) -> u8 {
        loop {
            if let Some(ch) = sbi_console_getchar() {
                break ch;
            }
        }
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            self.write_byte(b);
        }
        Ok(())
    }
}

/// Uses SBI to write data to debug console
#[allow(clippy::cast_possible_wrap)]
fn sbi_console_putchar(ch: u8) {
    // Safety: We are running under an SEE
    unsafe {
        asm!(
            "ecall",
            in("a7") 1,
            inout("a0") ch as isize => _,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Uses SBI to read data from debug console
fn sbi_console_getchar() -> Option<u8> {
    let ch: isize;
    // Safety: We are running under an SEE
    unsafe {
        asm!(
            "ecall",
            in("a7") 2,
            out("a0") ch,
            options(nomem, nostack, preserves_flags),
        );
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (ch != -1).then_some(ch as u8)
}
