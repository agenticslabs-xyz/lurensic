//! WebAssembly host ABI, version 1. The module has four exports and no imports.
//!
//! * `kagami_abi_version() -> u32` returns the ABI version.
//! * `kagami_alloc(len: usize) -> *mut u8` allocates a buffer for the host to write input into.
//! * `kagami_free(ptr: *mut u8, len: usize)` frees input and output buffers.
//! * `kagami_call(ptr, len) -> u64` takes a JSON envelope and returns a JSON
//!   response packed as `(out_ptr << 32) | out_len`.
//!
//! The module imports nothing from the host, so it has no clock, no randomness
//! and no I/O.

use crate::api::Runtime;
use std::cell::RefCell;

thread_local! {
    static RUNTIME: RefCell<Runtime> = RefCell::new(Runtime::default());
}

#[no_mangle]
pub extern "C" fn kagami_abi_version() -> u32 {
    crate::ABI_VERSION
}

#[no_mangle]
pub extern "C" fn kagami_alloc(len: usize) -> *mut u8 {
    let buf = vec![0u8; len].into_boxed_slice();
    Box::into_raw(buf) as *mut u8
}

/// # Safety
/// `ptr`/`len` must come from `kagami_alloc` or `kagami_call` and be freed once.
#[no_mangle]
pub unsafe extern "C" fn kagami_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
}

/// # Safety
/// `ptr`/`len` must describe a live buffer obtained from `kagami_alloc`.
#[no_mangle]
pub unsafe extern "C" fn kagami_call(ptr: *const u8, len: usize) -> u64 {
    let input = std::slice::from_raw_parts(ptr, len);
    let out = RUNTIME.with(|rt| rt.borrow_mut().handle(input));
    let bytes = out.into_bytes().into_boxed_slice();
    let out_len = bytes.len();
    let out_ptr = Box::into_raw(bytes) as *mut u8;
    ((out_ptr as usize as u64) << 32) | out_len as u64
}
