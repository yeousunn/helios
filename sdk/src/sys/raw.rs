//! Raw syscall implementation and unsafe primitives for x86_64.
//!
//! This is the ONLY module in the `sdk` crate allowed to contain `unsafe`
//! code and inline assembly (PLAN.md §7.1). All other modules must be
//! `#![forbid(unsafe_code)]`.

use core::alloc::{GlobalAlloc, Layout};

use super::super::heap::GlobalHeap;
use super::super::syscall::{RawSyscalls, SysReply};

/// x86_64 backend: the `syscall` instruction with the register conventions of
/// syscall-abi §2 (`rcx`/`r11` are clobbered by the instruction; args arrive
/// in `rdi/rsi/rdx/r10/r8/r9`, returns in `rax/rdx/rsi/rdi/r8/r9`).
#[cfg(target_arch = "x86_64")]
pub struct X86_64Syscalls;

#[cfg(target_arch = "x86_64")]
impl RawSyscalls for X86_64Syscalls {
    fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
        let (status, tag, w0, w1, w2, w3): (u64, u64, u64, u64, u64, u64);
        // SAFETY: `syscall` transfers control to the kernel's syscall entry,
        // which per the ratified ABI (sdk/docs/syscall-abi.md §2) reads the
        // number from rax and arguments from rdi/rsi/rdx/r10/r8/r9, returns
        // status in rax and tag/words in rdx/rsi/rdi/r8/r9, and clobbers
        // rcx/r11. It touches no user memory for register-sized messages, so
        // the stack is not used.
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") number as u64 => status,
                inlateout("rdi") args[0] => w1,
                inlateout("rsi") args[1] => w0,
                inlateout("rdx") args[2] => tag,
                inlateout("r10") args[3] => _,
                inlateout("r8") args[4] => w2,
                inlateout("r9") args[5] => w3,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack)
            );
        }
        SysReply {
            status: status as i32,
            tag,
            words: [w0, w1, w2, w3],
        }
    }
}

/// Stub for non-x86_64 targets (host tests).
#[cfg(not(target_arch = "x86_64"))]
pub struct X86_64Syscalls;

#[cfg(not(target_arch = "x86_64"))]
impl RawSyscalls for X86_64Syscalls {
    fn raw(&mut self, _number: u32, _args: [u64; 6]) -> SysReply {
        panic!("X86_64Syscalls not available on this target")
    }
}

/// Safe wrapper for copying bytes to a raw virtual address.
/// SAFETY: Caller must ensure `dst` is a valid, writable, mapped address
/// with at least `src.len()` bytes available.
pub fn raw_copy_to_va(dst: u64, src: &[u8]) {
    // SAFETY: Caller guarantees the safety contract.
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, src.len());
    }
}

/// Safe wrapper for copying bytes from a raw virtual address.
/// SAFETY: Caller must ensure `src` is a valid, readable, mapped address
/// with at least `dst.len()` bytes available.
pub fn raw_copy_from_va(src: u64, dst: &mut [u8]) {
    // SAFETY: Caller guarantees the safety contract.
    unsafe {
        core::ptr::copy_nonoverlapping(src as *const u8, dst.as_mut_ptr(), dst.len());
    }
}

/// Safe wrapper for reading a NUL-terminated string from a raw virtual address.
/// Returns the string bytes (without NUL) or None if not valid.
/// SAFETY: Caller must ensure `ptr` is a valid, readable, mapped address.
pub fn raw_cstr_from_va(ptr: u64) -> Option<&'static [u8]> {
    if ptr == 0 {
        return None;
    }
    // SAFETY: Caller guarantees the safety contract.
    unsafe {
        let p = ptr as *const u8;
        let mut n = 0usize;
        while *p.add(n) != 0 {
            n += 1;
        }
        Some(core::slice::from_raw_parts(p, n))
    }
}

/// Safe wrapper for reading an array of `u64` pointers from a raw virtual address.
/// Returns a slice of the pointers, or None if the address is null.
/// SAFETY: Caller must ensure `ptr` is a valid, readable, mapped address
/// with at least `count * 8` bytes available.
pub fn raw_ptr_array_from_va(ptr: u64, count: usize) -> Option<&'static [u64]> {
    if ptr == 0 {
        return None;
    }
    // SAFETY: Caller guarantees the safety contract.
    unsafe { Some(core::slice::from_raw_parts(ptr as *const u64, count)) }
}

/// Safe wrapper for copying bytes from a raw virtual address into a `[u64; 3]`.
/// This avoids the unsafe `from_raw_parts_mut` cast in callers.
/// SAFETY: Caller must ensure `src` is a valid, readable, mapped address
/// with at least 24 bytes available.
pub fn raw_copy_from_va_to_u64x3(src: u64, dst: &mut [u64; 3]) {
    // SAFETY: `dst` is a valid reference to a `[u64; 3]` (24 bytes).
    // The cast to `&mut [u8]` is safe because it's the same memory layout.
    let dst_bytes = unsafe { core::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u8, 24) };
    raw_copy_from_va(src, dst_bytes);
}

/// A `GlobalAlloc` wrapper over `GlobalHeap` that binaries can use as their
/// `#[global_allocator]`. This is the single shared implementation — every
/// userspace binary (init, child, ps, vfs, console, auth, personality bins)
/// uses this instead of defining its own `LocalHeap` wrapper.
///
/// Usage:
/// ```rust,ignore
/// use sdk::sys::SysHeap;
///
/// #[global_allocator]
/// static HEAP: SysHeap = SysHeap::new();
///
/// // In _start, after mapping heap pages:
/// HEAP.init(start, len).unwrap();
/// ```
pub struct SysHeap {
    inner: GlobalHeap,
}

impl SysHeap {
    pub const fn new() -> Self {
        Self {
            inner: GlobalHeap::new(),
        }
    }

    /// Install the backing span. Fails with `EBADSTATE` on double-init.
    pub fn init(&self, start: usize, len: usize) -> Result<(), i32> {
        self.inner.init(start, len)
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

impl Default for SysHeap {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for SysHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.inner
            .alloc(layout)
            .map_or(core::ptr::null_mut(), |p| p.as_ptr())
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

/// Macro to define the `_start` entry point that captures the 3-word header
/// (argc, argv pointer, envp pointer) from the initial stack before any
/// Rust prologue runs, then jumps to the provided `main` function.
///
/// The v0.2 entry contract (crafted by the launcher, see `servers/process`):
/// ```text
/// [rsp - 8]  = argc (u64)
/// [rsp - 16] = argv* (u64, VA of pointer array)
/// [rsp - 24] = envp* (u64, VA of pointer array)
/// ```
///
/// Usage:
/// ```rust,ignore
/// sdk::sys::entry_point!(my_main);
///
/// extern "C" fn my_main(argc: u64, argv_va: u64, envp_va: u64) -> ! {
///     loop {}
/// }
/// ```
#[macro_export]
macro_rules! entry_point {
    ($main:ident) => {
        core::arch::global_asm!(
            ".global _start",
            "_start:",
            "mov rdi, [rsp - 8]",   // argc
            "mov rsi, [rsp - 16]",  // argv* (VA)
            "mov rdx, [rsp - 24]",  // envp* (VA)
            "sub rsp, 64",
            "and rsp, -16",
            "jmp {main}",
            main = sym $main,
        );
    };
}
