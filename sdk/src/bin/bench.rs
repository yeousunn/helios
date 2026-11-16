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

use ipc::{CapSlot, Message, Rights};
use sdk::bootinfo::BootInfo;
use sdk::heap::RegionSource;
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS, INIT_HEAP_VA_BASE};
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
const WARMUP_ITERS: u64 = 100;
const MEASURE_ITERS: u64 = 10000;

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

    // Factory endpoint round-trip (like init).
    let factory_ep = {
        let mut sys = Syscalls::new(raw);
        let reply = sys
            .invoke(info.factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    if factory_ep == 0 {
        return Err(fail_code(STEP_SETUP, 0xE0));
    }
    {
        let mut sys = Syscalls::new(raw);
        mark(&mut sys, debug_ep, STEP_SETUP, factory_ep as u64);
    }

    // Bootstrap heap (same as init).
    let self_as = info.self_as.ok_or(fail_code(STEP_SETUP, 0xE4))?;
    let region = info.region(0).ok_or(fail_code(STEP_SETUP, 0xE5))?.handle;
    let heap_span = {
        let mut src = RegionSource::new(raw, region, self_as, INIT_HEAP_VA_BASE, HEAP_CHUNK);
        for chunk in 0..HEAP_CHUNKS {
            src.grow(HEAP_CHUNK)
                .map_err(|e| fail_code(STEP_SETUP, ((e as u64 & 0xFF) << 8) | (chunk + 1)))?;
        }
        (
            INIT_HEAP_VA_BASE as usize,
            (HEAP_CHUNKS * HEAP_CHUNK) as usize,
        )
    };
    HEAP.init(heap_span.0, heap_span.1)
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;

    {
        let mut sys = Syscalls::new(raw);
        mark(&mut sys, debug_ep, STEP_BENCH_START, 0);
    }

    // Run all benchmarks.
    bench_call_reply(raw, debug_ep, factory_ep, self_as, region)?;
    bench_send_recv(raw, debug_ep, factory_ep)?;
    bench_notification_wake(raw, debug_ep, factory_ep, self_as, region)?;
    bench_context_switch_same_as(raw, debug_ep, factory_ep, self_as, region)?;
    bench_context_switch_diff_as(raw, debug_ep, factory_ep, self_as, region)?;
    bench_map_unmap_4k(raw, debug_ep, factory_ep, self_as, region)?;

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

/// Benchmark: call/reply round trip.
fn bench_call_reply(
    raw: &mut X86_64Syscalls,
    debug_ep: Handle,
    factory_ep: Handle,
    self_as: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);

    // Create a server endpoint for the call/reply test.
    let server_ep = mint_ep(&mut sys, factory_ep)?;

    // Spawn a server thread that does reply_recv in a loop.
    let server_entry = thread_entry_reply_recv_loop as *const () as u64;
    let (server_thread, _server_pid) = spawn_thread(
        &mut sys,
        factory_ep,
        self_as,
        region,
        server_ep,
        server_entry,
    )?;

    // Bind death notification to clean up.
    let death_notif = mint_notification(&mut sys, factory_ep)?;
    sys.invoke(
        server_thread,
        &msg_with_cap(
            methods::thread::BIND_DEATH_NOTIFICATION,
            death_notif,
            Rights::SIGNAL,
        ),
    )
    .map_err(err_to_u64)?;

    // Give the server thread time to start (it will park in reply_recv).
    sys.yield_now().map_err(err_to_u64)?;

    // Warmup.
    for _ in 0..WARMUP_ITERS {
        let m = Message::new(0x1000);
        let _ = sys.call(server_ep, &m).map_err(err_to_u64)?;
    }

    // Measure.
    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        let m = Message::new(0x1000);
        let _ = sys.call(server_ep, &m).map_err(err_to_u64)?;
    }
    let end = rdtsc();

    let cycles_per_iter = (end - start) / MEASURE_ITERS;
    mark_bench(&mut sys, debug_ep, "call_reply", cycles_per_iter);

    // Cleanup: kill server thread.
    let _ = sys.invoke(server_thread, &Message::new(methods::thread::KILL));
    let _ = sys.cap_revoke(server_thread, 1);

    Ok(())
}

/// Benchmark: one-way send (send + recv on other side).
fn bench_send_recv(raw: &mut X86_64Syscalls, debug_ep: Handle, factory_ep: Handle) -> Result<()> {
    let mut sys = Syscalls::new(raw);

    let ep = mint_ep(&mut sys, factory_ep)?;

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
    factory_ep: Handle,
    self_as: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);

    let notif = mint_notification(&mut sys, factory_ep)?;

    // Spawn a thread that blocks on the notification.
    let recv_entry = thread_entry_recv_loop as *const () as u64;
    let (waiter_thread, _pid) =
        spawn_thread_with_notif(&mut sys, factory_ep, self_as, region, notif, recv_entry)?;

    // Bind death notification.
    let death_notif = mint_notification(&mut sys, factory_ep)?;
    sys.invoke(
        waiter_thread,
        &msg_with_cap(
            methods::thread::BIND_DEATH_NOTIFICATION,
            death_notif,
            Rights::SIGNAL,
        ),
    )
    .map_err(err_to_u64)?;

    // Yield to let the waiter park.
    sys.yield_now().map_err(err_to_u64)?;

    // Warmup.
    for _ in 0..WARMUP_ITERS {
        let mut m = Message::new(methods::notification::SIGNAL);
        m.words[0] = 1;
        sys.invoke(notif, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?; // let waiter run and re-block
    }

    // Measure signal-to-wake (signal + waiter unblocks).
    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        let mut m = Message::new(methods::notification::SIGNAL);
        m.words[0] = 1;
        sys.invoke(notif, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?; // let waiter run and re-block
    }
    let end = rdtsc();

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
    factory_ep: Handle,
    self_as: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);

    // Create two threads in the same AS that ping-pong via endpoints.
    let ep1 = mint_ep(&mut sys, factory_ep)?;
    let ep2 = mint_ep(&mut sys, factory_ep)?;

    let recv_entry = thread_entry_recv_loop as *const () as u64;
    let (thread1, _) = spawn_thread(&mut sys, factory_ep, self_as, region, ep1, recv_entry)?;
    let (thread2, _) = spawn_thread(&mut sys, factory_ep, self_as, region, ep2, recv_entry)?;

    // Bind death notifications.
    let death1 = mint_notification(&mut sys, factory_ep)?;
    let death2 = mint_notification(&mut sys, factory_ep)?;
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

    // Start both threads (they will park on recv).
    sys.yield_now().map_err(err_to_u64)?;

    // Warmup: ping-pong between the two threads.
    let m = Message::new(0x1002);
    for _ in 0..WARMUP_ITERS {
        sys.send(ep1, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
        let _ = sys.recv(ep2).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
    }

    // Measure context switch (thread1 -> kernel -> thread2 -> kernel -> thread1).
    let start = rdtsc();
    for _ in 0..MEASURE_ITERS {
        sys.send(ep1, &m).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
        let _ = sys.recv(ep2).map_err(err_to_u64)?;
        sys.yield_now().map_err(err_to_u64)?;
    }
    let end = rdtsc();

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
    factory_ep: Handle,
    self_as: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);

    // Create a second address space.
    let as2 = {
        let reply = sys
            .invoke(
                factory_ep,
                &Message::new(methods::factory::NEW_ADDRESS_SPACE),
            )
            .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
        reply.words[0] as Handle
    };
    if as2 == 0 {
        return Err(fail_code(STEP_SETUP, 0xE1));
    }

    // Endpoints are kernel objects not tied to AS, so we can use the same endpoint.
    let ep = mint_ep(&mut sys, factory_ep)?;

    // Spawn thread in first AS.
    let recv_entry = thread_entry_recv_loop as *const () as u64;
    let (thread1, _) = spawn_thread(&mut sys, factory_ep, self_as, region, ep, recv_entry)?;

    // Spawn thread in second AS.
    let (thread2, _) = spawn_thread(&mut sys, factory_ep, as2, region, ep, recv_entry)?;

    // Bind death notifications.
    let death1 = mint_notification(&mut sys, factory_ep)?;
    let death2 = mint_notification(&mut sys, factory_ep)?;
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
    _factory_ep: Handle,
    self_as: Handle,
    region: Handle,
) -> Result<()> {
    let mut sys = Syscalls::new(raw);

    // Carve a frame for mapping (we use ANON for benchmarks so we don't need the frame cap).
    // But we carve one anyway to have it available if needed.
    let _frame = carve_frame(&mut sys, region)?;

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

/// Mint a new endpoint capability.
fn mint_ep(sys: &mut Syscalls<X86_64Syscalls>, factory: Handle) -> Result<Handle> {
    let reply = sys
        .invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
    let handle = reply.words[0] as Handle;
    if handle == 0 {
        return Err(fail_code(STEP_SETUP, 0xE2));
    }
    Ok(handle)
}

/// Mint a new notification capability.
fn mint_notification(sys: &mut Syscalls<X86_64Syscalls>, factory: Handle) -> Result<Handle> {
    let reply = sys
        .invoke(factory, &Message::new(methods::factory::NEW_NOTIFICATION))
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
    let handle = reply.words[0] as Handle;
    if handle == 0 {
        return Err(fail_code(STEP_SETUP, 0xE3));
    }
    Ok(handle)
}

/// Thread entry point: loops on `recv` using handle 1 (bootstrap endpoint).
/// This runs in a fresh thread with no heap; uses only raw syscalls.
extern "C" fn thread_entry_recv_loop() -> ! {
    let mut raw = X86_64Syscalls;
    let mut sys = Syscalls::new(&mut raw);
    let bootstrap_ep: Handle = 1; // handle 1 = bootstrap endpoint installed by NEW_THREAD
    loop {
        let _ = sys.recv(bootstrap_ep);
    }
}

/// Thread entry point: loops on `reply_recv` using handle 1 (bootstrap endpoint).
/// Used for the call/reply benchmark server thread.
extern "C" fn thread_entry_reply_recv_loop() -> ! {
    let mut raw = X86_64Syscalls;
    let mut sys = Syscalls::new(&mut raw);
    let bootstrap_ep: Handle = 1; // handle 1 = bootstrap endpoint installed by NEW_THREAD
    let msg = Message::new(0);
    loop {
        let _ = sys.reply_recv(bootstrap_ep, &msg);
    }
}

/// Spawn a thread with the given entry function that parks on `recv`/`reply_recv` at the given endpoint.
fn spawn_thread(
    sys: &mut Syscalls<X86_64Syscalls>,
    factory: Handle,
    aspace: Handle,
    _region: Handle,
    ep: Handle,
    entry_pc: u64,
) -> Result<(Handle, u64)> {
    let mut m = Message::new(methods::factory::NEW_THREAD);
    m.tag = m.tag.with_caps(3);
    m.words[0] = entry_pc;
    let _ = m.set_descriptor(0, CapSlot::pack(aspace, Rights::MAP.union(Rights::GRANT)));
    let _ = m.set_descriptor(1, CapSlot::NULL); // fault EP
    let _ = m.set_descriptor(2, CapSlot::pack(ep, Rights::RECV)); // bootstrap EP = the endpoint to park on

    let reply = sys
        .invoke(factory, &m)
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;

    let thread_cap = reply.words[0] as Handle;
    let pid = reply.words[2];
    if thread_cap == 0 {
        return Err(fail_code(STEP_SETUP, 0xE4));
    }

    Ok((thread_cap, pid))
}

/// Spawn a thread that blocks on a notification.
fn spawn_thread_with_notif(
    sys: &mut Syscalls<X86_64Syscalls>,
    factory: Handle,
    aspace: Handle,
    _region: Handle,
    notif: Handle,
    entry_pc: u64,
) -> Result<(Handle, u64)> {
    let mut m = Message::new(methods::factory::NEW_THREAD);
    m.tag = m.tag.with_caps(3);
    m.words[0] = entry_pc;
    let _ = m.set_descriptor(0, CapSlot::pack(aspace, Rights::MAP.union(Rights::GRANT)));
    let _ = m.set_descriptor(1, CapSlot::NULL);
    let _ = m.set_descriptor(2, CapSlot::pack(notif, Rights::RECV)); // bootstrap EP = notification

    let reply = sys
        .invoke(factory, &m)
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;

    let thread_cap = reply.words[0] as Handle;
    let pid = reply.words[2];
    if thread_cap == 0 {
        return Err(fail_code(STEP_SETUP, 0xE5));
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

/// Carve a 4 KiB frame from the region.
fn carve_frame(sys: &mut Syscalls<X86_64Syscalls>, region: Handle) -> Result<Handle> {
    let mut carve = Message::new(methods::region::CARVE);
    carve.words[0] = 4096;
    carve.words[1] = 4096;
    let reply = sys
        .invoke(region, &carve)
        .map_err(|e| fail_code(STEP_SETUP, e as u64))?;
    let handle = reply.words[0] as Handle;
    if handle == 0 {
        return Err(fail_code(STEP_SETUP, 0xE6));
    }
    Ok(handle)
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
