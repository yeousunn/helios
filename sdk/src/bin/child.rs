//! v0 spawn payload: the app that a PS-spawned child runs (embedded into the
//! process server via `CHILD_IMAGE`; design §2.4/§2.6 SPAWN).
//!
//! Protocol hygiene: every child receives its ADR-009 bootstrap package
//! first (PS's `deliver` parks per chunk until consumed — skipping this
//! deadlocks the spawner), then reads its initial stack, which PS crafts
//! (v0 convention, `servers/process/src/bin/ps.rs`):
//!
//! ```text
//! entry rsp = sdk::layout::USER_STACK_TOP
//! [rsp - 8]  = argc (u64)
//! [rsp - 16] = argv* (u64, VA of pointer array)
//! [rsp - 24] = envp* (u64, VA of pointer array)
//! ```
//!
//! The smoke behavior: exit with argv[0] parsed as a decimal number — proof
//! that arg-window → PS → child-stack data flow and exit-status propagation
//! (PS `WAIT`) work end to end.
#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use core::panic::PanicInfo;

#[allow(unused_imports)]
use ipc::Message;
use sdk::sys::SysHeap;
use sdk::syscall::{Syscalls, X86_64Syscalls};

/// The sdk rlib links `alloc`; a handler satisfies the link even though this
/// child allocates nothing in the smoke path (initializing the heap is only
/// needed for attack mode).
#[global_allocator]
static HEAP: SysHeap = SysHeap::new();

sdk::sys::entry_point!(child_main);

/// Parse argv[0] directly from the entry stack without allocating.
/// Returns the exit status (argv[0] as decimal) or -1/-2 on parse failure.
fn parse_argv0_status(argc: u64, argv_va: u64) -> i32 {
    use sdk::sys::{raw_cstr_from_va, raw_ptr_array_from_va};
    if argc == 0 {
        return -1;
    }
    let argv_ptrs = raw_ptr_array_from_va(argv_va, argc as usize).unwrap_or(&[]);
    if argv_ptrs.is_empty() || argv_ptrs[0] == 0 {
        return -1;
    }
    let arg0 = raw_cstr_from_va(argv_ptrs[0]).unwrap_or(&[]);
    if arg0.is_empty() || !arg0[0].is_ascii_digit() {
        return -2;
    }
    let mut v: i32 = 0;
    for &c in arg0 {
        if !c.is_ascii_digit() {
            break;
        }
        v = v.saturating_mul(10).saturating_add((c - b'0') as i32);
    }
    v
}

fn child_main(argc: u64, argv_va: u64, _envp_va: u64) -> ! {
    let mut raw = X86_64Syscalls;

    // 1. Receive the bootstrap package first (no allocation needed).
    let package = {
        let mut sys = Syscalls::new(&mut raw);
        match sdk::bootstrap::receive(&mut sys) {
            Ok(p) => p,
            Err(e) => Syscalls::new(&mut raw).exit(e),
        }
    };

    // 2. Fast path: smoke test only needs argv[0] as decimal exit status.
    //    Parse it directly from the entry stack without any heap allocation.
    let smoke_status = parse_argv0_status(argc, argv_va);

    // 3. S11 attack mode: `argv[0] == "attack"` runs the kernel-hardening attack
    //    cases (sdk::attack). This path needs a heap for allocations.
    //    Check argv[0] again via the non-allocating parser to avoid heap init
    //    unless actually needed.
    let is_attack = {
        use sdk::sys::{raw_cstr_from_va, raw_ptr_array_from_va};
        if argc == 0 {
            false
        } else {
            let argv_ptrs = raw_ptr_array_from_va(argv_va, argc as usize).unwrap_or(&[]);
            !argv_ptrs.is_empty()
                && argv_ptrs[0] != 0
                && raw_cstr_from_va(argv_ptrs[0]) == Some(b"attack")
        }
    };

    if is_attack {
        // Initialize heap for attack mode (allocates via Vec in attack cases).
        use sdk::heap::RegionSource;
        use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS};
        const CHILD_HEAP_VA_BASE: u64 = 0x4000_0000;
        let span = {
            let mut src = RegionSource::new(
                &mut raw,
                package.region,
                package.aspace,
                CHILD_HEAP_VA_BASE,
                HEAP_CHUNK,
            );
            src.map_startup(HEAP_CHUNKS)
        };
        let (heap_start, heap_len) = match span {
            Ok(v) => v,
            Err(e) => Syscalls::new(&mut raw).exit(e),
        };
        if let Err(e) = HEAP.init(heap_start, heap_len) {
            Syscalls::new(&mut raw).exit(e);
        }

        let status = {
            let mut sys = Syscalls::new(&mut raw);
            sdk::attack::run(&mut sys, &package)
        };
        Syscalls::new(&mut raw).exit(status)
    }

    // 4. Diagnostic: echo argv through console if provided (optional, no alloc).
    if let Some(console) = package.optional.get(2).copied().flatten() {
        if argc != 0 {
            let mut sys = Syscalls::new(&mut raw);
            let mut m = ipc::Message::new(sdk::methods::console::WRITE);
            let mut n = 0usize;
            let mut put = |bytes: &[u8]| {
                for &b in bytes {
                    if n < 32 {
                        m.words[n / 8] |= (b as u64) << ((n % 8) * 8);
                        n += 1;
                    }
                }
            };
            use sdk::sys::{raw_cstr_from_va, raw_ptr_array_from_va};
            let argv_ptrs = raw_ptr_array_from_va(argv_va, argc as usize).unwrap_or(&[]);
            put(b"argv=");
            for i in 0..argc as usize {
                if i != 0 {
                    put(b" ");
                }
                if i < argv_ptrs.len() && argv_ptrs[i] != 0 {
                    if let Some(a) = raw_cstr_from_va(argv_ptrs[i]) {
                        put(a);
                    }
                }
            }
            // envp is optional and not parsed for the smoke path.
            let _ = sys.send(console.handle(), &m);
        }
    }

    // 5. Exit with argv[0] as decimal status (smoke test convention).
    Syscalls::new(&mut raw).exit(smoke_status)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(0x0BAD_0001)
}
