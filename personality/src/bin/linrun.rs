//! `/linrun` — the POSIX/Linux emulation demo (ADR-044 + ADR-046). It loads a
//! *foreign* (Linux-ABI) thread, flags it foreign so the kernel routes its raw
//! `syscall`s to this process (a `FOREIGN_SYSCALL` call + `Thread::TRAP_READ`
//! for the frame), decodes them with `personality::foreign::dispatch`, performs
//! the native operation, and replies with the Linux result.
//!
//! The emulated thread and this emulator share one address space (v0 model),
//! so pointer arguments are direct addresses. This demo runs a small
//! in-binary raw-syscall stub (`write(1, …)` + `exit(0)`); the ELF loader for
//! an external musl binary builds on the same loop.
//!
//! Package: optional[0] = VFS, [1] = stdin, [2] = stdout (console),
//! [3] = the foreign route endpoint (minted by the launcher, ADR-046).

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::global_asm;
use core::panic::PanicInfo;

use ipc::Message;
use personality::layout::HEAP_VA_BASE;
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS, USER_STACK_TOP};
use sdk::syscall::{Syscalls, X86_64Syscalls};

#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

/// The foreign program to run: a freestanding static x86_64-linux ELF (no
/// libc; raw `write`+`exit`). Loaded and executed like any Linux binary.
static LIN_ELF: &[u8] = include_bytes!("../../assets/lin_args");

/// Load an ET_EXEC ELF into this process's own AS (shared with the emulated
/// thread): carve + map a frame per page of every PT_LOAD, then copy the file
/// bytes straight to the segment VA. Returns the entry PC.
fn load_elf<R: sdk::syscall::RawSyscalls>(
    sys: &mut Syscalls<R>,
    as_cap: u32,
    region: u32,
    bytes: &[u8],
) -> Result<u64, i32> {
    let elf = sdk::elf::ElfImage::parse(bytes)?;
    for i in 0..elf.segment_count {
        let seg = elf.segment(i).ok_or(-1)?;
        let first = seg.vaddr & !0xFFF;
        let pages = (seg.vaddr + seg.memsz - first).div_ceil(4096);
        for p in 0..pages {
            let va = first + p * 4096;
            let mut carve = Message::new(sdk::methods::region::CARVE);
            carve.words[0] = 4096;
            carve.words[1] = 4096;
            let frame = sys.invoke(region, &carve)?.words[0] as u32;
            if frame == 0 {
                return Err(-12); // ENOMEM
            }
            let mut map = Message::new(sdk::methods::aspace::MAP);
            map.tag = map.tag.with_caps(1);
            map.words[0] = va;
            map.words[1] = 0b111; // R | W | X (v0: no W^X yet)
            let _ = map.set_descriptor(
                0,
                ipc::CapSlot::pack(frame, ipc::Rights::READ.union(ipc::Rights::WRITE)),
            );
            sys.invoke(as_cap, &map)?;
        }
        // SAFETY: the segment VA is now mapped in this AS; copy its contents.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(seg.offset as usize),
                seg.vaddr as *mut u8,
                seg.filesz as usize,
            );
        }
    }
    Ok(elf.entry)
}

/// `foreign::Host` over direct memory (shared AS) + the console endpoint.
struct Emu<'a> {
    raw: &'a mut X86_64Syscalls,
    out: Option<u32>,
}

impl personality::foreign::Host for Emu<'_> {
    fn mem_read(&mut self, addr: u64, buf: &mut [u8]) -> i64 {
        // SAFETY: the emulated image shares this AS; addr is a valid pointer.
        unsafe {
            core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len());
        }
        buf.len() as i64
    }
    fn mem_write(&mut self, addr: u64, data: &[u8]) -> i64 {
        // SAFETY: as above.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
        }
        data.len() as i64
    }
    fn write_fd(&mut self, fd: i32, data: &[u8]) -> i64 {
        if fd != 1 && fd != 2 {
            return -9; // EBADF
        }
        if let Some(h) = self.out {
            let mut sys = Syscalls::new(self.raw);
            for chunk in data.chunks(sdk::methods::console::TEXT_BYTES) {
                let mut m = Message::new(sdk::methods::console::WRITE);
                m.words = sdk::methods::pack_console_text(chunk);
                let _ = sys.send(h, &m);
            }
        }
        data.len() as i64
    }
    fn read_fd(&mut self, _fd: i32, _out: &mut [u8]) -> i64 {
        -9 // EBADF (no stdin in this demo)
    }
    fn close_fd(&mut self, _fd: i32) -> i64 {
        -9
    }
    fn getpid(&mut self) -> i64 {
        1
    }
    fn gettid(&mut self) -> i64 {
        1
    }
    fn brk(&mut self, requested: u64) -> i64 {
        requested as i64 // accept and report unchanged
    }
    fn mmap_anon(&mut self, _len: usize) -> i64 {
        -12 // ENOMEM: no heap in this demo
    }
}

extern "C" fn linrun_main() -> ! {
    let mut raw = X86_64Syscalls;
    let package = {
        let mut sys = Syscalls::new(&mut raw);
        match sdk::bootstrap::receive(&mut sys) {
            Ok(p) => p,
            Err(e) => exit(&mut raw, e),
        }
    };

    // The personality lib uses `alloc`; stand up the heap (mostly unused here).
    let span = {
        let mut src = RegionSource::new(
            &mut raw,
            package.region,
            package.aspace,
            HEAP_VA_BASE,
            HEAP_CHUNK,
        );
        src.map_startup(HEAP_CHUNKS)
    };
    let (start, len) = match span {
        Ok(v) => v,
        Err(e) => exit(&mut raw, e),
    };
    if HEAP.init(start, len).is_err() {
        exit(&mut raw, 0xE2);
    }

    let out = package
        .optional
        .get(2)
        .copied()
        .flatten()
        .map(|cs| cs.handle())
        .filter(|h| *h != 0);
    let fep = match package
        .optional
        .get(3)
        .copied()
        .flatten()
        .map(|cs| cs.handle())
        .filter(|h| *h != 0)
    {
        Some(h) => h,
        None => exit(&mut raw, 0x50), // no route endpoint
    };
    let notif = package.session_notifications[3];

    // Create the emulated thread, quiesce it, flag it foreign, bind its death.
    let entry = {
        let mut sys = Syscalls::new(&mut raw);
        match load_elf(&mut sys, package.aspace, package.region, LIN_ELF) {
            Ok(e) => e,
            Err(e) => exit(&mut raw, 0x40 | (e & 0xF)),
        }
    };

    // Craft the Linux initial stack at USER_STACK_TOP (where the kernel's
    // fresh-thread context puts RSP): [argc][argv...][NULL][envp...][NULL]
    // [auxv pairs][AT_NULL], with the argv string above it. A real libc
    // `_start` reads this; our freestanding test binary reads argv[0].
    {
        let mut sys = Syscalls::new(&mut raw);
        // Map one page at USER_STACK_TOP (above the process's own stack).
        let mut carve = Message::new(sdk::methods::region::CARVE);
        carve.words[0] = 4096;
        carve.words[1] = 4096;
        let frame = match sys.invoke(package.region, &carve) {
            Ok(r) => r.words[0] as u32,
            Err(e) => exit(&mut raw, 0x60 | (e & 0xF)),
        };
        let mut map = Message::new(sdk::methods::aspace::MAP);
        map.tag = map.tag.with_caps(1);
        map.words[0] = USER_STACK_TOP;
        map.words[1] = 0b011; // R | W
        let _ = map.set_descriptor(
            0,
            ipc::CapSlot::pack(frame, ipc::Rights::READ.union(ipc::Rights::WRITE)),
        );
        if let Err(e) = sys.invoke(package.aspace, &map) {
            exit(&mut raw, 0x61 | (e & 0xF));
        }
        // SAFETY: the page is mapped; write the standard Linux startup layout.
        unsafe {
            let base = USER_STACK_TOP as *mut u64;
            let arg = b"helios-linux-abi\n\0";
            let s = (USER_STACK_TOP + 0x100) as *mut u8;
            core::ptr::copy_nonoverlapping(arg.as_ptr(), s, arg.len());
            *base.add(0) = 1; // argc
            *base.add(1) = s as u64; // argv[0]
            *base.add(2) = 0; // argv terminator
            *base.add(3) = 0; // envp terminator
            *base.add(4) = 6; // AT_PAGESZ
            *base.add(5) = 4096;
            *base.add(6) = 9; // AT_ENTRY
            *base.add(7) = entry;
            *base.add(8) = 0; // AT_NULL
            *base.add(9) = 0;
        }
    }
    let child = {
        let mut sys = Syscalls::new(&mut raw);
        let mut m = Message::new(sdk::methods::thread::THREAD_CREATE);
        m.words[0] = entry;
        match sys.invoke(package.thread, &m) {
            Ok(r) => r.words[0] as u32,
            Err(e) => exit(&mut raw, 0x51 | (e & 0xF)),
        }
    };
    if child == 0 {
        exit(&mut raw, 0x52);
    }
    {
        let mut sys = Syscalls::new(&mut raw);
        // SUSPEND → SET_FOREIGN(handle) → BIND_DEATH → RESUME.
        let _ = sys.invoke(child, &Message::new(sdk::methods::thread::SUSPEND));
        let mut sf = Message::new(sdk::methods::thread::SET_FOREIGN);
        sf.words[0] = fep as u64;
        if let Err(e) = sys.invoke(child, &sf) {
            exit(&mut raw, 0x53 | (e & 0xF));
        }
        let mut bd = Message::new(sdk::methods::thread::BIND_DEATH_NOTIFICATION);
        bd.tag = bd.tag.with_caps(1);
        let _ = bd.set_descriptor(0, ipc::CapSlot::pack(notif, ipc::Rights::SIGNAL));
        let _ = sys.invoke(child, &bd);
        let _ = sys.invoke(child, &Message::new(sdk::methods::thread::RESUME));
    }

    // Emulate: serve routed syscalls until the emulated thread dies.
    loop {
        let routed = {
            let mut sys = Syscalls::new(&mut raw);
            sys.recv_nonblock(fep)
        };
        match routed {
            Ok(msg) if msg.tag.label() == ipc::labels::kernel::FOREIGN_SYSCALL => {
                // The kernel saves the trap frame in its NATIVE register
                // layout (num=rax, cap=rdi, tag=rsi, w0=rdx, w1=r10, w2=r8,
                // w3=r9). A Linux `syscall` uses the same physical registers
                // (rdi,rsi,rdx,r10,r8,r9), so the Linux args are
                // [cap, tag.0, w0, w1, w2, w3].
                let num = msg.words[0];
                let frame = {
                    let mut sys = Syscalls::new(&mut raw);
                    match sys.invoke(child, &Message::new(sdk::methods::thread::TRAP_READ)) {
                        Ok(r) => r,
                        Err(_) => continue,
                    }
                };
                let args = [
                    msg.words[1],   // rdi = linux arg0
                    frame.words[0], // rsi = linux arg1
                    frame.words[1], // rdx = linux arg2
                    frame.words[2], // r10 = linux arg3
                    frame.words[3], // r8  = linux arg4
                    msg.words[2],   // r9  = linux arg5
                ];
                let action = {
                    let mut host = Emu { raw: &mut raw, out };
                    personality::foreign::dispatch(num, args, &mut host)
                };
                match action {
                    personality::foreign::Action::Return(v) => {
                        let mut rep = Message::new(ipc::labels::kernel::FOREIGN_SYSCALL);
                        rep.words[0] = v as u64;
                        let mut sys = Syscalls::new(&mut raw);
                        let _ = sys.reply(&rep);
                    }
                    personality::foreign::Action::Exit(code) => {
                        // Linux `exit`: terminate the emulated thread (the
                        // kernel's own exit is not on its routable set). The
                        // child is parked in its exit syscall — force it out.
                        let mut e = Message::new(sdk::methods::thread::EXIT);
                        e.words[0] = code as i64 as u64;
                        let mut sys = Syscalls::new(&mut raw);
                        let _ = sys.invoke(child, &e);
                        break;
                    }
                }
            }
            Ok(_) => {
                let mut sys = Syscalls::new(&mut raw);
                let _ = sys.reply(&Message::new(0xFFFF));
            }
            Err(_) => {
                // No routed call pending: has the emulated thread died?
                let dead = {
                    let mut sys = Syscalls::new(&mut raw);
                    sys.recv_nonblock(notif).is_ok()
                };
                if dead {
                    break;
                }
                let mut sys = Syscalls::new(&mut raw);
                let _ = sys.yield_now();
            }
        }
    }

    exit(&mut raw, 0)
}

fn exit(raw: &mut X86_64Syscalls, code: i32) -> ! {
    personality::runtime::exit(&mut Syscalls::new(raw), code)
}

// Entry: the SDK native path (PS delivers an ADR-009 package to handle 1 and
// jumps here). No crafted-argv entry contract is needed for this demo.
global_asm!(
    ".global _start",
    "_start:",
    "and rsp, -16",
    "call {main}",
    main = sym linrun_main,
);

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
