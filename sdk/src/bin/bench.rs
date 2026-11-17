//! Helios microbenchmarks — measures core kernel operations with the cycle counter.
//!
//! Built for `x86_64-unknown-none` with `--features user`:
//! ```text
//! cargo build -p sdk --bin bench --features user --target x86_64-unknown-none --release
//! ```
//! Entry: `_start` with `rdi` = pointer to the kernel-written BootInfo block.
//!
//! Benchmarks (printed as parseable lines for `tools/bench.sh --compare`):
//!   BENCH call_reply <cycles>
//!   BENCH send_recv <cycles>
//!   BENCH notification_wake <cycles>
//!   BENCH context_switch_same_as <cycles>
//!   BENCH context_switch_diff_as <cycles>
//!   BENCH map_4k <cycles>
//!   BENCH unmap_4k <cycles>

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::{CapSlot, Message, Rights};

use sdk::bootinfo::BootInfo;
use sdk::heap::RegionSource;
use sdk::layout::{CHILD_STACK_PAGES, HEAP_CHUNK, INIT_HEAP_VA_BASE, USER_STACK_TOP};
use sdk::methods;
use sdk::sys::{init_entry_point, rdtsc, SysHeap};
use sdk::syscall::{Handle, Status, Syscalls, X86_64Syscalls};

/// Log marker prefix for debug endpoint (same as init).
const MARK: u64 = 0x494E_4954_0000_0000;
const STEP_ALIVE: u64 = 1;
const STEP_BOOTINFO: u64 = 2;
const STEP_SETUP: u64 = 3;
const STEP_BENCH_START: u64 = 4;
const STEP_DONE: u64 = 0x0F;

const DEBUG_LABEL: u16 = 0x0001;

#[global_allocator]
static HEAP: SysHeap = SysHeap::new();

type Result<T> = core::result::Result<T, u64>;

/// Minimal bench configuration.
const WARMUP_ITERS: u64 = 10;
const MEASURE_ITERS: u64 = 1000;
const BENCH_HEAP_CHUNKS: u64 = 2;

/// Stack size for bench threads (64 KiB = 16 pages).
const THREAD_STACK_PAGES: u64 = CHILD_STACK_PAGES;
const THREAD_STACK_SIZE: u64 = THREAD_STACK_PAGES * 4096;

/// Next available stack top (starts below initial stack, decrements per thread).
static NEXT_STACK_TOP: AtomicU64 = AtomicU64::new(USER_STACK_TOP - THREAD_STACK_SIZE);

/// Global handle for thread entry points to find their endpoint (THREAD_CREATE
/// threads share the cap table; no bootstrap endpoint at handle 1).
static THREAD_ENTRY_EP: AtomicU32 = AtomicU32::new(0);

init_entry_point!(bench_main);

fn bench_main(bootinfo_ptr: *const u8) -> ! {
    let info = match sdk::sys::read_bootinfo(bootinfo_ptr) {
        Ok(info) => info,
        Err(e) => exit_with(fail_code(STEP_BOOTINFO, e)),
    };
    let mut raw = X86_64Syscalls;
    {
        let mut sys = Syscalls::new(&mut raw);
        mark(&mut sys, info.debug_ep, STEP_ALIVE, 0);
        mark(
            &mut sys,
            info.debug_ep,
            STEP_BOOTINFO,
            info.region_count as u64,
        );
    }

    match run(&mut raw, &info) {
        Ok(()) => {
            let mut sys = Syscalls::new(&mut raw);
            mark(&mut sys, info.debug_ep, STEP_DONE, 0);
            sys.exit(0)
        }
        Err(code) => exit_with(code),
    }
}

fn run(raw: &mut X86_64Syscalls, info: &BootInfo) -> Result<()> {
    let debug_ep = info.debug_ep;

    // The actual Factory capability from BootInfo for creating kernel objects.
    let factory_cap = info.factory;

    // Bootstrap heap (smaller than init for faster bench startup).
    let self_as = info.self_as.ok_or(fail_code(STEP_SETUP, 0xE4))?;
    let self_thread = info.self_thread.ok_or(fail_code(STEP_SETUP, 0xEA))?;
    let region = info.region(0).ok_or(fail_code(STEP_SETUP, 0xE5))?.handle;
    let heap_span = {
        let mut src = RegionSource::new(raw, region, self_as, INIT_HEAP_VA_BASE, HEAP_CHUNK);
        for chunk in 0..BENCH_HEAP_CHUNKS {
            src.grow(HEAP_CHUNK)
                .map_err(|e| fail_code(STEP_SETUP, ((e as u64 & 0xFF) << 8) | (chunk + 1)))?;
        }
        (
            INIT_HEAP_VA_BASE as usize,
            (BENCH_HEAP_CHUNKS * HEAP_CHUNK) as usize,
        )
    };
    HEAP.init(heap_span.0, heap_span.1)
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;

    {
        let mut sys = Syscalls::new(raw);
        mark(&mut sys, debug_ep, STEP_BENCH_START, 0);
    }

    // Run all benchmarks.
    bench_call_reply(raw, debug_ep, factory_cap, self_as, self_thread, region)?;
    bench_send_recv(raw, debug_ep, factory_cap)?;
    bench_notification_wake(raw, debug_ep, factory_cap, self_as, self_thread, region)?;
    bench_context_switch_same_as(raw, debug_ep, factory_cap, self_as, self_thread, region)?;
    bench_context_switch_diff_as(raw, debug_ep, factory_cap, self_as, self_thread, region)?;
    bench_map_unmap_4k(raw, debug_ep, factory_cap, self_as, region)?;

    Ok(())
}

/// Helper to send a debug marker with the benchmark result.
fn mark_bench(sys: &mut Syscalls<X86_64Syscalls>, debug_ep: Handle, name: &str, cycles: u64) {
    let mut m = Message::new(DEBUG_LABEL);
    let name_hash = hash_name(name);
    m.words[0] = MARK | 0xFE00 | (name_hash & 0xFF); // step 0xFE = bench
    m.words[1] = cycles;
    m.words[2] = name_hash >> 8;
    m.words[3] = 0;
    let _ = sys.send(debug_ep, &m);
}

fn hash_name(name: &str) -> u64 {
    let mut h: u64 = 1469598103934665603; // FNV offset basis
    for b in name.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211); // FNV prime
    }
    h
}

/// Convert syscall Status (i32) to our u64 error.
fn err_to_u64(e: Status) -> u64 {
    e as u64
}

/// Carve and map a stack region for a new thread.
/// Uses a custom stack top below the initial thread's stack to avoid overlap.
/// Returns (stack_top_va, stack_frame_handle, stack_base).
fn carve_stack(
    sys: &mut Syscalls<X86_64Syscalls>,
    region: Handle,
    aspace: Handle,
) -> Result<(u64, Handle, u64)> {
    // Carve a contiguous region for the stack (THREAD_STACK_PAGES * 4 KiB).
    let mut carve = Message::new(methods::region::CARVE);
    carve.words[0] = THREAD_STACK_SIZE;
    carve.words[1] = 4096; // page-aligned
    let reply = sys
        .invoke(region, &carve)
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
    let frame_handle = reply.words[0] as Handle;
    if frame_handle == 0 {
        return Err(fail_code(STEP_SETUP, 0xE7));
    }

    // Get a unique stack top for this thread.
    let stack_top = NEXT_STACK_TOP.fetch_sub(THREAD_STACK_SIZE, Ordering::SeqCst);
    let stack_base = stack_top - THREAD_STACK_SIZE;

    // Map the stack frames.
    for i in 0..THREAD_STACK_PAGES {
        let vaddr = stack_base + i * 4096;
        let mut m = Message::new(methods::aspace::MAP);
        m.words[0] = vaddr;
        m.words[1] =
            u64::from(methods::map_flags::R | methods::map_flags::W | methods::map_flags::ANON);
        sys.invoke(aspace, &m).map_err(err_to_u64)?;
    }

    Ok((stack_top, frame_handle, stack_base))
}

/// Spawn a thread in the same address space using THREAD_CREATE on self_thread.
/// Returns (thread_cap, stack_frame_handle, stack_base).
fn spawn_thread_same_as(
    sys: &mut Syscalls<X86_64Syscalls>,
    self_thread: Handle,
    self_as: Handle,
    region: Handle,
    entry_pc: u64,
) -> Result<(Handle, Handle, u64)> {
    // Carve a custom stack for this thread (unique stack top per thread).
    let (stack_top, frame_handle, stack_base) = carve_stack(sys, region, self_as)?;

    // THREAD_CREATE on self_thread (same process): w0 = entry_pc, w1 = stack_top.
    let mut m = Message::new(methods::thread::THREAD_CREATE);
    m.words[0] = entry_pc;
    m.words[1] = stack_top;

    let reply = sys
        .invoke(self_thread, &m)
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;

    let thread_cap = reply.words[0] as Handle;
    if thread_cap == 0 {
        return Err(fail_code(STEP_SETUP, 0xE8));
    }

    Ok((thread_cap, frame_handle, stack_base))
}

/// Spawn a thread in a different address space using NEW_THREAD (ADR-088 uniform packing).
/// Returns (thread_cap, pid).
fn spawn_thread_diff_as(
    sys: &mut Syscalls<X86_64Syscalls>,
    factory: Handle,
    aspace: Handle,
    region: Handle,
    bootstrap_ep: Handle,
    entry_pc: u64,
) -> Result<(Handle, u64)> {
    // Carve a custom stack for this thread in the target AS.
    let (stack_top, _frame_handle, _stack_base) = carve_stack(sys, region, aspace)?;

    // NEW_THREAD with ADR-088 uniform packing (cap_count=2):
    // w0 = entry PC, w1 = initial user stack top
    // caps[0] = AddressSpace (with MAP|GRANT), caps[1] = bootstrap endpoint (with RECV)
    let mut m = Message::new(methods::factory::NEW_THREAD);
    m.tag = m.tag.with_caps(2);
    m.words[0] = entry_pc;
    m.words[1] = stack_top;
    let _ = m.set_descriptor(0, CapSlot::pack(aspace, Rights::MAP.union(Rights::GRANT)));
    let _ = m.set_descriptor(1, CapSlot::pack(bootstrap_ep, Rights::RECV));

    let reply = sys
        .invoke(factory, &m)
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;

    let thread_cap = reply.words[0] as Handle;
    let pid = reply.words[2];
    if thread_cap == 0 {
        return Err(fail_code(STEP_SETUP, 0xE9));
    }

    Ok((thread_cap, pid))
}

/// Create a message with a single capability descriptor.
fn msg_with_cap(method: u16, cap: Handle, rights: Rights) -> Message {
    let mut m = Message::new(method);
    m.tag = m.tag.with_caps(1);
    let _ = m.set_descriptor(0, CapSlot::pack(cap, rights));
    m
}

/// Benchmark: call/reply round trip.
fn bench_call_reply(
    raw: &mut X86_64Syscalls,
    debug_ep: Handle,
    factory: Handle,
    self_as: Handle,
    self_thread: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);

    // Create a server endpoint for the call/reply test.
    let server_ep = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    if server_ep == 0 {
        return Err(fail_code(STEP_SETUP, 0xE0));
    }

    // Spawn a server thread in the same AS that does recv then reply_recv in a loop.
    // For THREAD_CREATE, the thread shares the cap table, so it can use server_ep directly.
    THREAD_ENTRY_EP.store(server_ep, Ordering::SeqCst);
    let server_entry = thread_entry_reply_recv_loop as *const () as u64;
    let (server_thread, _server_frame, _server_stack_base) =
        spawn_thread_same_as(&mut sys, self_thread, self_as, region, server_entry)?;

    mark(&mut sys, debug_ep, 0xF0, 1); // debug: after spawn_thread_same_as

    // Bind death notification to clean up.
    let death_notif = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_NOTIFICATION))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    mark(&mut sys, debug_ep, 0xF0, 2); // debug: after mint_notification

    sys.invoke(
        server_thread,
        &msg_with_cap(
            methods::thread::BIND_DEATH_NOTIFICATION,
            death_notif,
            Rights::SIGNAL,
        ),
    )
    .map_err(err_to_u64)?;
    mark(&mut sys, debug_ep, 0xF0, 3); // debug: after BIND_DEATH_NOTIFICATION

    // Give the server thread time to start (it will park in recv then reply_recv).
    sys.yield_now().map_err(err_to_u64)?;
    mark(&mut sys, debug_ep, 0xF0, 4); // debug: after yield_now

    // Warmup.
    for _ in 0..WARMUP_ITERS {
        let m = Message::new(0x1000);
        let _ = sys.call(server_ep, &m).map_err(err_to_u64)?;
    }

    mark(&mut sys, debug_ep, 0xF0, 5); // debug: call_reply warmup done

    // Measure.
    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        let m = Message::new(0x1000);
        let _ = sys.call(server_ep, &m).map_err(err_to_u64)?;
    }
    let end = rdtsc();

    mark(&mut sys, debug_ep, 0xF0, 6); // debug: call_reply measure done

    let cycles_per_iter = (end - start) / MEASURE_ITERS;
    mark_bench(&mut sys, debug_ep, "call_reply", cycles_per_iter);

    // Cleanup: kill server thread.
    let _ = sys.invoke(server_thread, &Message::new(methods::thread::KILL));
    let _ = sys.cap_revoke(server_thread, 1);

    Ok(())
}

/// Benchmark: one-way send (send + recv on other side).
fn bench_send_recv(raw: &mut X86_64Syscalls, debug_ep: Handle, factory: Handle) -> Result<()> {
    let mut sys = Syscalls::new(raw);

    let ep = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };

    // Warmup: send and recv in same thread (measures send+recv path without thread switch).
    for _ in 0..WARMUP_ITERS {
        let m = Message::new(0x1001);
        sys.send(ep, &m).map_err(err_to_u64)?;
        let _ = sys.recv(ep).map_err(err_to_u64)?;
    }

    // Measure send+recv in same thread (lower bound).
    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        let m = Message::new(0x1001);
        sys.send(ep, &m).map_err(err_to_u64)?;
        let _ = sys.recv(ep).map_err(err_to_u64)?;
    }
    let end = rdtsc();

    let cycles_per_iter = (end - start) / MEASURE_ITERS;
    mark_bench(&mut sys, debug_ep, "send_recv", cycles_per_iter);

    Ok(())
}

/// Benchmark: notification signal-to-wake.
fn bench_notification_wake(
    raw: &mut X86_64Syscalls,
    debug_ep: Handle,
    factory: Handle,
    self_as: Handle,
    self_thread: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);
    mark(&mut sys, debug_ep, 0xF2, 1); // debug: notification_wake start

    // Create bootstrap endpoint for the waiter thread.
    let bootstrap_ep = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    mark(&mut sys, debug_ep, 0xF2, 2); // debug: after mint_ep bootstrap

    // Create notification for signaling.
    let notif = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_NOTIFICATION))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    mark(&mut sys, debug_ep, 0xF2, 3); // debug: after mint_notification

    // Spawn a thread in the same AS that blocks on the bootstrap endpoint.
    // For THREAD_CREATE, the thread shares the cap table, so it can use bootstrap_ep directly.
    THREAD_ENTRY_EP.store(bootstrap_ep, Ordering::SeqCst);
    let recv_entry = thread_entry_recv_loop as *const () as u64;
    let (waiter_thread, _waiter_frame, _waiter_stack_base) =
        spawn_thread_same_as(&mut sys, self_thread, self_as, region, recv_entry)?;
    mark(&mut sys, debug_ep, 0xF2, 4); // debug: after spawn_thread_same_as

    // Bind notification to the waiter thread (so recv on bootstrap_ep wakes on signal).
    sys.invoke(
        waiter_thread,
        &msg_with_cap(methods::thread::BIND_NOTIFICATION, notif, Rights::SIGNAL),
    )
    .map_err(err_to_u64)?;
    mark(&mut sys, debug_ep, 0xF2, 5); // debug: after BIND_NOTIFICATION

    // Bind death notification.
    let death_notif = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_NOTIFICATION))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    mark(&mut sys, debug_ep, 0xF2, 6); // debug: after mint_notification death
    sys.invoke(
        waiter_thread,
        &msg_with_cap(
            methods::thread::BIND_DEATH_NOTIFICATION,
            death_notif,
            Rights::SIGNAL,
        ),
    )
    .map_err(err_to_u64)?;
    mark(&mut sys, debug_ep, 0xF2, 7); // debug: after BIND_DEATH_NOTIFICATION

    // Yield to let the waiter park.
    sys.yield_now().map_err(err_to_u64)?;
    mark(&mut sys, debug_ep, 0xF2, 8); // debug: after yield_now

    // Warmup.
    for _ in 0..WARMUP_ITERS {
        let mut m = Message::new(methods::notification::SIGNAL);
        m.words[0] = 1;
        sys.invoke(notif, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?; // let waiter run and re-block
    }
    mark(&mut sys, debug_ep, 0xF2, 9); // debug: warmup done

    // Measure signal-to-wake (signal + waiter unblocks).
    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        let mut m = Message::new(methods::notification::SIGNAL);
        m.words[0] = 1;
        sys.invoke(notif, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?; // let waiter run and re-block
    }
    let end = rdtsc();
    mark(&mut sys, debug_ep, 0xA, 0); // debug: measure done

    let cycles_per_iter = (end - start) / MEASURE_ITERS;
    mark_bench(&mut sys, debug_ep, "notification_wake", cycles_per_iter);

    // Cleanup.
    let _ = sys.invoke(waiter_thread, &Message::new(methods::thread::KILL));
    let _ = sys.cap_revoke(waiter_thread, 1);

    Ok(())
}

/// Benchmark: context switch between threads in the same address space.
fn bench_context_switch_same_as(
    raw: &mut X86_64Syscalls,
    debug_ep: Handle,
    factory: Handle,
    self_as: Handle,
    self_thread: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);
    mark(&mut sys, debug_ep, 0xF3, 1); // debug: context_switch_same_as start

    // Create two endpoints for ping-pong.
    let ep1 = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    let ep2 = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    mark(&mut sys, debug_ep, 0xF3, 2); // debug: after mint_ep

    let recv_entry = thread_entry_recv_loop as *const () as u64;

    // Spawn thread1 using ep1.
    THREAD_ENTRY_EP.store(ep1, Ordering::SeqCst);
    let (thread1, _frame1, _stack_base1) =
        spawn_thread_same_as(&mut sys, self_thread, self_as, region, recv_entry)?;

    // Spawn thread2 using ep2.
    THREAD_ENTRY_EP.store(ep2, Ordering::SeqCst);
    let (thread2, _frame2, _stack_base2) =
        spawn_thread_same_as(&mut sys, self_thread, self_as, region, recv_entry)?;

    mark(&mut sys, debug_ep, 0xF3, 3); // debug: after spawn_thread_same_as

    // Bind death notifications.
    let death1 = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_NOTIFICATION))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    let death2 = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_NOTIFICATION))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    mark(&mut sys, debug_ep, 0xF3, 4); // debug: after mint_notification
    sys.invoke(
        thread1,
        &msg_with_cap(
            methods::thread::BIND_DEATH_NOTIFICATION,
            death1,
            Rights::SIGNAL,
        ),
    )
    .map_err(err_to_u64)?;
    sys.invoke(
        thread2,
        &msg_with_cap(
            methods::thread::BIND_DEATH_NOTIFICATION,
            death2,
            Rights::SIGNAL,
        ),
    )
    .map_err(err_to_u64)?;
    mark(&mut sys, debug_ep, 0xF3, 5); // debug: after BIND_DEATH_NOTIFICATION

    // Start both threads (they will park on recv).
    sys.yield_now().map_err(err_to_u64)?;
    mark(&mut sys, debug_ep, 0xF3, 6); // debug: after yield_now

    // Warmup: ping-pong between the two threads.
    let m = Message::new(0x1002);
    for _ in 0..WARMUP_ITERS {
        sys.send(ep1, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
        let _ = sys.recv(ep2).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
    }
    mark(&mut sys, debug_ep, 0xF3, 7); // debug: warmup done

    // Measure context switch (thread1 -> kernel -> thread2 -> kernel -> thread1).
    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        sys.send(ep1, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
        let _ = sys.recv(ep2).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
    }
    let end = rdtsc();
    mark(&mut sys, debug_ep, 0xF3, 8); // debug: measure done

    let cycles_per_iter = (end - start) / MEASURE_ITERS;
    mark_bench(
        &mut sys,
        debug_ep,
        "context_switch_same_as",
        cycles_per_iter,
    );

    // Cleanup.
    let _ = sys.invoke(thread1, &Message::new(methods::thread::KILL));
    let _ = sys.cap_revoke(thread1, 1);
    let _ = sys.invoke(thread2, &Message::new(methods::thread::KILL));
    let _ = sys.cap_revoke(thread2, 1);

    Ok(())
}

/// Benchmark: context switch between threads in different address spaces.
fn bench_context_switch_diff_as(
    raw: &mut X86_64Syscalls,
    debug_ep: Handle,
    factory: Handle,
    self_as: Handle,
    self_thread: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);
    mark(&mut sys, debug_ep, 0xF1, 1); // debug: bench_context_switch_diff_as start

    // Create a second address space.
    let as2 = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_ADDRESS_SPACE))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    if as2 == 0 {
        return Err(fail_code(STEP_SETUP, 0xE1));
    }

    // Endpoints are kernel objects not tied to AS, so we can use the same endpoint.
    let ep = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };

    // Create bootstrap endpoints for each thread.
    let _bootstrap_ep1 = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    let bootstrap_ep2 = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };

    // Spawn thread in first AS (same AS as bench) using THREAD_CREATE.
    let recv_entry = thread_entry_recv_loop as *const () as u64;
    THREAD_ENTRY_EP.store(ep, Ordering::SeqCst);
    let (thread1, _frame1, _stack_base1) =
        spawn_thread_same_as(&mut sys, self_thread, self_as, region, recv_entry)?;

    // Spawn thread in second AS using NEW_THREAD with ADR-088 uniform packing.
    let (thread2, _pid) =
        spawn_thread_diff_as(&mut sys, factory, as2, region, bootstrap_ep2, recv_entry)?;

    // Bind death notifications.
    let death1 = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_NOTIFICATION))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    let death2 = {
        let reply = sys
            .invoke(factory, &Message::new(methods::factory::NEW_NOTIFICATION))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    sys.invoke(
        thread1,
        &msg_with_cap(
            methods::thread::BIND_DEATH_NOTIFICATION,
            death1,
            Rights::SIGNAL,
        ),
    )
    .map_err(err_to_u64)?;
    sys.invoke(
        thread2,
        &msg_with_cap(
            methods::thread::BIND_DEATH_NOTIFICATION,
            death2,
            Rights::SIGNAL,
        ),
    )
    .map_err(err_to_u64)?;

    sys.yield_now().map_err(err_to_u64)?;

    // Warmup.
    let m = Message::new(0x1003);
    for _ in 0..WARMUP_ITERS {
        sys.send(ep, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
        let _ = sys.recv(ep).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
    }

    // Measure.
    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        sys.send(ep, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
        let _ = sys.recv(ep).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
    }
    let end = rdtsc();

    let cycles_per_iter = (end - start) / MEASURE_ITERS;
    mark_bench(
        &mut sys,
        debug_ep,
        "context_switch_diff_as",
        cycles_per_iter,
    );

    // Cleanup.
    let _ = sys.invoke(thread1, &Message::new(methods::thread::KILL));
    let _ = sys.cap_revoke(thread1, 1);
    let _ = sys.invoke(thread2, &Message::new(methods::thread::KILL));
    let _ = sys.cap_revoke(thread2, 1);

    // Destroy the second AS.
    let m = Message::new(methods::aspace::DESTROY);
    sys.invoke(as2, &m).map_err(err_to_u64)?;

    Ok(())
}

/// Benchmark: map and unmap 4 KiB page.
fn bench_map_unmap_4k(
    raw: &mut X86_64Syscalls,
    debug_ep: Handle,
    _factory: Handle,
    self_as: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);

    // Carve a frame for mapping (we use ANON for benchmarks so we don't need the frame cap).
    // But we carve one anyway to have it available if needed.
    let _frame = {
        let mut carve = Message::new(methods::region::CARVE);
        carve.words[0] = 4096;
        carve.words[1] = 4096;
        let reply = sys
            .invoke(region, &carve)
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };

    // Map benchmark: MAP a 4 KiB page at a fixed VA.
    const MAP_VA: u64 = 0x200000; // 2 MiB, page-aligned

    use sdk::methods::map_flags;
    let map_flags_val = map_flags::R | map_flags::W | map_flags::ANON; // ANON so we don't need the frame cap

    // Warmup: map/unmap ANON (no frame cap needed).
    for _ in 0..WARMUP_ITERS {
        let mut m = Message::new(methods::aspace::MAP);
        m.words[0] = MAP_VA;
        m.words[1] = u64::from(map_flags_val);
        sys.invoke(self_as, &m).map_err(err_to_u64)?;
        let mut um = Message::new(methods::aspace::UNMAP);
        um.words[0] = MAP_VA;
        um.words[1] = 1;
        sys.invoke(self_as, &um).map_err(err_to_u64)?;
    }

    // Measure MAP (ANON).
    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        let mut m = Message::new(methods::aspace::MAP);
        m.words[0] = MAP_VA;
        m.words[1] = u64::from(map_flags_val);
        sys.invoke(self_as, &m).map_err(err_to_u64)?;
    }
    let end = rdtsc();
    let map_cycles = (end - start) / MEASURE_ITERS;
    mark_bench(&mut sys, debug_ep, "map_4k", map_cycles);

    // Clean up the last mapping.
    let mut um = Message::new(methods::aspace::UNMAP);
    um.words[0] = MAP_VA;
    um.words[1] = 1;
    sys.invoke(self_as, &um).map_err(err_to_u64)?;

    // Measure UNMAP.
    // First map again.
    let mut m = Message::new(methods::aspace::MAP);
    m.words[0] = MAP_VA;
    m.words[1] = u64::from(map_flags_val);
    sys.invoke(self_as, &m).map_err(err_to_u64)?;

    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        let mut um = Message::new(methods::aspace::UNMAP);
        um.words[0] = MAP_VA;
        um.words[1] = 1;
        sys.invoke(self_as, &um).map_err(err_to_u64)?;

        // Re-map for next iteration.
        let mut m = Message::new(methods::aspace::MAP);
        m.words[0] = MAP_VA;
        m.words[1] = u64::from(map_flags_val);
        sys.invoke(self_as, &m).map_err(err_to_u64)?;
    }
    let end = rdtsc();
    let unmap_cycles = (end - start) / MEASURE_ITERS;
    mark_bench(&mut sys, debug_ep, "unmap_4k", unmap_cycles);

    // Final cleanup.
    let mut um = Message::new(methods::aspace::UNMAP);
    um.words[0] = MAP_VA;
    um.words[1] = 1;
    sys.invoke(self_as, &um).map_err(err_to_u64)?;

    Ok(())
}

/// Thread entry point for THREAD_CREATE threads: loops on `recv` using the
/// endpoint handle stored in THREAD_ENTRY_EP (shared cap table, no bootstrap EP).
fn thread_entry_recv_loop() -> ! {
    let mut raw = X86_64Syscalls;
    let mut sys = Syscalls::new(&mut raw);
    let ep = THREAD_ENTRY_EP.load(Ordering::SeqCst);
    loop {
        let _ = sys.recv(ep);
    }
}

/// Thread entry point for THREAD_CREATE threads: loops on `recv` then `reply_recv`
/// using the endpoint handle stored in THREAD_ENTRY_EP.
fn thread_entry_reply_recv_loop() -> ! {
    let mut raw = X86_64Syscalls;
    let mut sys = Syscalls::new(&mut raw);
    let ep = THREAD_ENTRY_EP.load(Ordering::SeqCst);
    // First recv: blocks until a call arrives, sets implicit reply cap, returns the call message.
    let _msg = sys.recv(ep).unwrap_or_else(|_| Message::new(0));
    // Reply to the first call and enter the reply_recv loop.
    let mut reply_msg = Message::new(0);
    loop {
        reply_msg = sys
            .reply_recv(ep, &reply_msg)
            .unwrap_or_else(|_| Message::new(0));
    }
}

/// Exit with a failure code.
fn exit_with(code: u64) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(code as i32)
}

const fn fail_code(step: u64, errno: u64) -> u64 {
    0xDEAD_0000_0000_0000 | ((step & 0xFF) << 16) | (errno & 0xFFFF)
}

/// Send a debug marker.
fn mark(sys: &mut Syscalls<X86_64Syscalls>, debug_ep: Handle, step: u64, value: u64) {
    let mut m = Message::new(DEBUG_LABEL);
    m.words[0] = MARK | step;
    m.words[1] = value;
    let _ = sys.send(debug_ep, &m);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit_with(0xDEAD_0000_0BAD_0000)
}
