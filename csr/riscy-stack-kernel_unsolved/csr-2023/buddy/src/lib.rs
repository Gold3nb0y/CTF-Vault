//! Buddy allocator

#![no_std]
#![feature(inline_const)]
#![feature(int_roundings)]
#![feature(pointer_byte_offsets)]
#![feature(pointer_is_aligned)]
#![feature(ptr_sub_ptr)]
#![feature(strict_provenance)]
#![feature(try_trait_v2)]
#![warn(clippy::missing_docs_in_private_items)]
#![warn(clippy::pedantic)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]

pub mod buddy;
pub mod linked_list;

pub use crate::buddy::Buddy;
