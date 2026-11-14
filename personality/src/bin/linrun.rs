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

extern crate alloc;

use core::arch::global_asm;
use core::panic::PanicInfo;

use ipc::Message;
use personality::layout::HEAP_VA_BASE;
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS};
use sdk::sys::{raw_copy_from_va, raw_copy_to_va, raw_cstr_from_va};
use sdk::syscall::{Syscalls, X86_64Syscalls};

#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

/// The foreign program to run: a freestanding static x86_64-linux ELF (no
/// libc; raw `write`+`exit`). Loaded and executed like any Linux binary.
static LIN_ELF: &[u8] = include_bytes!("../../assets/musl_cwd");

/// The default demo program's argv[0].
const DEFAULT_ARGV0: &[u8] = b"helios-linux-abi\n";

/// busybox (Phase 3): a minimal static x86_64-linux-musl build (see
/// `assets/busybox.build.sh`). When the launcher passes native args, they
/// select a busybox applet instead of the default demo: the guest argv is
/// `<applet> <args…>` (multi-call invocation, basename(argv[0])).
static BUSYBOX_ELF: &[u8] = include_bytes!("../../assets/busybox");

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
        // The segment pages are mapped R|W|X in this AS by the loop above.
        // Zero the whole region (BSS = memsz - filesz) one page at a time,
        // then copy the file contents over it.
        const ZERO_PAGE: [u8; 4096] = [0; 4096];
        for p in 0..pages {
            raw_copy_to_va(first + p * 4096, &ZERO_PAGE);
        }
        let off = seg.offset as usize;
        let filesz = seg.filesz as usize;
        if let Some(src) = bytes.get(off..).and_then(|s| s.get(..filesz)) {
            raw_copy_to_va(seg.vaddr, src);
        }
    }
    Ok(elf.entry)
}

/// `foreign::Host` over direct memory (shared AS) + the console endpoint +
/// an optional VFS client (emulated `open`/`read`/`close` of real files).
struct Emu<'a> {
    raw: &'a mut X86_64Syscalls,
    child: u32,
    buf: &'a mut alloc::vec::Vec<u8>,
    vfs: Option<&'a mut personality::vfs::VfsClient>,
    region: u32,
    aspace: u32,
    /// Bump pointer for emulated anonymous `mmap`.
    mmap_bump: &'a mut u64,
    /// Current emulated program break.
    brk_cur: &'a mut u64,
    /// Per-VFS-fd directory cursor for emulated `getdents64`
    /// (`u64::MAX` = end-of-directory reached).
    dents_cookie: &'a mut [u64; 16],
}

/// Base VAs for emulated anonymous memory (distinct from the image, the Linux
/// stack, the stub and the personality heap/windows).
const MMAP_VA_BASE: u64 = 0x0000_6000_0000_0000;
const BRK_VA_BASE: u64 = 0x0000_6100_0000_0000;

impl Emu<'_> {
    /// Carve + map `len` bytes of zero-filled anonymous RW memory at `va`.
    fn map_pages(&mut self, va: u64, len: usize) -> bool {
        let pages = len.div_ceil(4096);
        for i in 0..pages {
            let mut sys = Syscalls::new(self.raw);
            let mut carve = Message::new(sdk::methods::region::CARVE);
            carve.words[0] = 4096;
            carve.words[1] = 4096;
            let frame = match sys.invoke(self.region, &carve) {
                Ok(r) => r.words[0] as u32,
                Err(_) => return false,
            };
            let mut map = Message::new(sdk::methods::aspace::MAP);
            map.tag = map.tag.with_caps(1);
            map.words[0] = va + i as u64 * 4096;
            map.words[1] = 0b011; // R | W
            let _ = map.set_descriptor(
                0,
                ipc::CapSlot::pack(frame, ipc::Rights::READ.union(ipc::Rights::WRITE)),
            );
            if sys.invoke(self.aspace, &map).is_err() {
                return false;
            }
        }
        true
    }
}

impl personality::foreign::Host for Emu<'_> {
    fn mem_read(&mut self, addr: u64, buf: &mut [u8]) -> i64 {
        // The emulated image shares this AS, and `addr` is a guest VA the
        // emulator mapped itself (load_elf / map_pages), so the copy target
        // is valid and `buf.len()` bytes fit inside the mapped span.
        raw_copy_from_va(addr, buf);
        buf.len() as i64
    }
    fn mem_write(&mut self, addr: u64, data: &[u8]) -> i64 {
        // As `mem_read`: the emulator owns every guest page it maps.
        raw_copy_to_va(addr, data);
        data.len() as i64
    }
    fn write_fd(&mut self, fd: i32, data: &[u8]) -> i64 {
        if fd != 1 && fd != 2 {
            return -9; // EBADF
        }
        // Buffer: the console send must happen AFTER this syscall's reply —
        // a nested blocking send while the foreign reply is pending corrupted
        // the resume (found: musl `write` then crashed at rip=0).
        self.buf.extend_from_slice(data);
        data.len() as i64
    }
    fn read_fd(&mut self, fd: i32, out: &mut [u8]) -> i64 {
        // stdio (0/1/2) has no VFS backing here; VFS slot fds are remapped to
        // Linux fd = slot + 3 (see `openat`).
        if fd < 3 {
            return -9; // EBADF
        }
        let Some(vfs) = self.vfs.as_deref_mut() else {
            return -9;
        };
        let mut sys = Syscalls::new(self.raw);
        match vfs.read(&mut sys, (fd as u32) - 3, out) {
            Ok(n) => n as i64,
            Err(e) => e as i64,
        }
    }
    fn close_fd(&mut self, fd: i32) -> i64 {
        if fd < 3 {
            return 0; // closing stdio is a no-op here
        }
        let Some(vfs) = self.vfs.as_deref_mut() else {
            return 0;
        };
        let mut sys = Syscalls::new(self.raw);
        match vfs.close(&mut sys, (fd as u32) - 3) {
            Ok(()) => 0,
            Err(e) => e as i64,
        }
    }
    fn getpid(&mut self) -> i64 {
        1
    }
    fn gettid(&mut self) -> i64 {
        1
    }
    fn brk(&mut self, requested: u64) -> i64 {
        if requested == 0 {
            return *self.brk_cur as i64; // query the current break
        }
        if requested <= *self.brk_cur {
            *self.brk_cur = requested;
            return requested as i64;
        }
        let cur = *self.brk_cur;
        if !self.map_pages(cur, (requested - cur) as usize) {
            return cur as i64; // grow failed: report the old break
        }
        *self.brk_cur = requested;
        requested as i64
    }
    fn mmap_anon(&mut self, len: usize) -> i64 {
        if len == 0 {
            return -22; // EINVAL
        }
        let pages = (len as u64).div_ceil(4096);
        let base = *self.mmap_bump;
        if !self.map_pages(base, len) {
            return -12; // ENOMEM
        }
        *self.mmap_bump += pages * 4096;
        base as i64
    }
    fn set_tls(&mut self, base: u64) -> i64 {
        // Thread::SET_TLS (kernel id 11) — the emulated thread's FS base.
        let mut sys = Syscalls::new(self.raw);
        let mut m = Message::new(sdk::methods::thread::SET_TLS);
        m.words[0] = base;
        match sys.invoke(self.child, &m) {
            Ok(_) => 0,
            Err(e) => e as i64,
        }
    }
    fn openat(&mut self, _dirfd: i32, path: &[u8], flags: u32) -> i64 {
        let Some(vfs) = self.vfs.as_deref_mut() else {
            return -2; // ENOENT (no VFS client wired)
        };
        let name = match path.iter().position(|&b| b == 0) {
            Some(n) => &path[..n],
            None => path,
        };
        // Translate Linux open(2) flags to the personality VFS's own O_* bits
        // (they differ: Linux O_CREAT=0x40/O_TRUNC=0x200 vs VFS 1/2).
        let mut pflags = 0u32;
        if flags & 0o3 != 0 {
            pflags |= personality::posix::O_WRONLY; // O_WRONLY | O_RDWR
        }
        if flags & 0x40 != 0 {
            pflags |= personality::posix::O_CREAT;
        }
        if flags & 0x200 != 0 {
            pflags |= personality::posix::O_TRUNC;
        }
        let mut sys = Syscalls::new(self.raw);
        // O_DIRECTORY (0x10000): a directory fd — `open_dir` resolves "/" to
        // the root (a plain `open` rejects a bare "/"; musl's opendir uses it).
        let r = if flags & 0x10000 != 0 {
            vfs.open_dir(&mut sys, name)
        } else {
            vfs.open(&mut sys, name, pflags)
        };
        match r {
            Ok(slot) => slot as i64 + 3,
            Err(e) => e as i64,
        }
    }
    fn getdents(&mut self, fd: i32, out: &mut [u8]) -> i64 {
        if fd < 3 {
            return -9; // EBADF
        }
        let slot = (fd as u32) - 3;
        if slot as usize >= self.dents_cookie.len() {
            return -9;
        }
        let slot = slot as usize;
        if self.dents_cookie[slot] == u64::MAX {
            return 0; // end-of-directory already reached
        }
        let Some(vfs) = self.vfs.as_deref_mut() else {
            return -9;
        };
        let mut off = 0usize;
        while out.len() - off >= 24 {
            let mut name = [0u8; 256];
            let cookie = self.dents_cookie[slot];
            let res = {
                let mut sys = Syscalls::new(self.raw);
                vfs.readdir_fd(&mut sys, slot as u32, cookie, &mut name)
            };
            match res {
                Ok(Some((next, kind, nlen))) => {
                    // struct linux_dirent64 { u64 ino; u64 off; u16 reclen;
                    // u8 type; char name[]; } padded to 8.
                    let reclen = (19 + nlen + 1 + 7) & !7;
                    if off + reclen > out.len() {
                        break; // does not fit: leave the cookie for the next call
                    }
                    let e = &mut out[off..off + reclen];
                    e.fill(0);
                    e[0..8].copy_from_slice(&(cookie.wrapping_add(1)).to_le_bytes()); // d_ino
                    e[8..16].copy_from_slice(&next.to_le_bytes()); // d_off
                    e[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                    e[18] = if kind == personality::vfs::KIND_DIR {
                        4 // DT_DIR
                    } else {
                        8 // DT_REG
                    };
                    e[19..19 + nlen].copy_from_slice(&name[..nlen]);
                    off += reclen;
                    if next == 0 {
                        self.dents_cookie[slot] = u64::MAX; // last entry
                        break;
                    }
                    self.dents_cookie[slot] = next;
                }
                Ok(None) => break,
                Err(e) => return if off > 0 { off as i64 } else { e as i64 },
            }
        }
        off as i64
    }
    fn fstat(&mut self, fd: i32) -> Result<personality::foreign::FileStat, i64> {
        if fd < 3 {
            return Err(-9); // EBADF
        }
        let Some(vfs) = self.vfs.as_deref_mut() else {
            return Err(-9);
        };
        let mut sys = Syscalls::new(self.raw);
        vfs.stat_fd(&mut sys, (fd as u32) - 3)
            .map(|s| personality::foreign::FileStat {
                kind: s.kind,
                mode: s.mode,
                size: s.size,
            })
            .map_err(|e| e as i64)
    }
    fn stat_path(&mut self, path: &[u8]) -> Result<personality::foreign::FileStat, i64> {
        let Some(vfs) = self.vfs.as_deref_mut() else {
            return Err(-2); // ENOENT
        };
        let name = match path.iter().position(|&b| b == 0) {
            Some(n) => &path[..n],
            None => path,
        };
        let mut sys = Syscalls::new(self.raw);
        match vfs.stat(&mut sys, name) {
            Ok(s) => Ok(personality::foreign::FileStat {
                kind: s.kind,
                mode: s.mode,
                size: s.size,
            }),
            Err(e) => Err(e as i64),
        }
    }
    fn chdir(&mut self, path: &[u8]) -> i64 {
        let Some(vfs) = self.vfs.as_deref_mut() else {
            return -2;
        };
        let name = match path.iter().position(|&b| b == 0) {
            Some(n) => &path[..n],
            None => path,
        };
        let mut sys = Syscalls::new(self.raw);
        vfs.chdir(&mut sys, name)
            .map(|_| 0)
            .unwrap_or_else(|e| e as i64)
    }
    fn getcwd(&mut self, out: &mut [u8]) -> i64 {
        // v0: the emulated program's cwd is always the VFS root.
        let p = b"/";
        let n = p.len().min(out.len());
        out[..n].copy_from_slice(&p[..n]);
        n as i64
    }
    fn readlink(&mut self, path: &[u8], out: &mut [u8]) -> i64 {
        let name = match path.iter().position(|&b| b == 0) {
            Some(n) => &path[..n],
            None => path,
        };
        if name == b"/proc/self/exe" {
            let exe = b"/linrun";
            let n = exe.len().min(out.len());
            out[..n].copy_from_slice(&exe[..n]);
            return n as i64;
        }
        -2 // ENOENT
    }
    fn getrandom(&mut self, out: &mut [u8]) -> i64 {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (0x5a ^ i) as u8;
        }
        out.len() as i64
    }
}

extern "C" fn linrun_main(argc: u64, argv_va: u64, _envp_va: u64) -> ! {
    let mut raw = X86_64Syscalls;
    // Copy the launcher's args into this frame at once: the crafted strings
    // live in the lower half of the top stack page, and the emulator's own
    // deep call chain (VFS connect, heap setup, ELF load) descends far enough
    // to overwrite them before the guest stack is built, so reading them later
    // yields empty/short slices. The copy is a fixed local array (our frame)
    // and it runs BEFORE the heap is up: `sdk::args::Args::new` copies every
    // argument into an owned Vec, which is an allocation failure (a panic)
    // on the uninitialized allocator. With no args we run the default
    // musl_cwd demo; with args we run the embedded busybox, where argv[1..]
    // selects an applet.
    let mut arg_buf = [[0u8; 48]; 8];
    let mut arg_len = [0usize; 8];
    let mut argn = 0usize;
    {
        // The v0.2 crafted stack (`sdk::args`): `argc` pointers at `argv_va`.
        let mut ptr_bytes = [0u8; 8];
        let mut i = 1usize;
        while i < argc as usize && argn < arg_buf.len() {
            raw_copy_from_va(argv_va + (i as u64) * 8, &mut ptr_bytes);
            let p = u64::from_le_bytes(ptr_bytes);
            if p == 0 {
                break;
            }
            let Some(a) = raw_cstr_from_va(p) else {
                break;
            };
            let n = a.len().min(arg_buf[argn].len());
            arg_buf[argn][..n].copy_from_slice(&a[..n]);
            arg_len[argn] = n;
            argn += 1;
            i += 1;
        }
    }
    let busybox = argn >= 1;
    let elf: &[u8] = if busybox { BUSYBOX_ELF } else { LIN_ELF };
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

    // Connect to the VFS (package `optional[0]`, the caller-supplied service
    // endpoint) so emulated `open`/`read`/`close` reach real files. Optional:
    // a demo run without a VFS cap still works (openat → ENOENT).
    let mut vfs = {
        let ep = package
            .optional
            .first()
            .copied()
            .flatten()
            .map(|cs| cs.handle())
            .filter(|h| *h != 0);
        match ep {
            Some(ep) => {
                let mut sys = Syscalls::new(&mut raw);
                personality::vfs::VfsClient::connect(
                    &mut sys,
                    package.aspace,
                    package.region,
                    ep,
                    package.session_notifications[0],
                )
                .ok()
            }
            None => None,
        }
    };

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
        match load_elf(&mut sys, package.aspace, package.region, elf) {
            Ok(e) => e,
            Err(e) => exit(&mut raw, 0x40 | (e & 0xF)),
        }
    };

    // Craft the Linux initial stack at a DEDICATED VA — NOT USER_STACK_TOP,
    // which is where the emulator's OWN main-thread Rust stack lives (sharing
    // it corrupts the emulated thread as soon as the emulator nests deeper
    // into the serve loop). A stackless stub, set as the child's entry, moves
    // RSP to here then jumps to the ELF entry.
    const STACK_BASE: u64 = 0x0000_7F00_0000_0000;
    const STACK_PAGES: u64 = 8; // 32 KiB
    const STUB_PAGE: u64 = 0x0000_0000_4000_0000;
    {
        let mut sys = Syscalls::new(&mut raw);
        // Map STACK_PAGES for the Linux stack.
        for i in 0..STACK_PAGES {
            let mut carve = Message::new(sdk::methods::region::CARVE);
            carve.words[0] = 4096;
            carve.words[1] = 4096;
            let frame = match sys.invoke(package.region, &carve) {
                Ok(r) => r.words[0] as u32,
                Err(e) => exit(&mut raw, 0x60 | (e & 0xF)),
            };
            let mut map = Message::new(sdk::methods::aspace::MAP);
            map.tag = map.tag.with_caps(1);
            map.words[0] = STACK_BASE + i * 4096;
            map.words[1] = 0b011; // R | W
            let _ = map.set_descriptor(
                0,
                ipc::CapSlot::pack(frame, ipc::Rights::READ.union(ipc::Rights::WRITE)),
            );
            if let Err(e) = sys.invoke(package.aspace, &map) {
                exit(&mut raw, 0x61 | (e & 0xF));
            }
        }
        // Map one page for the RSP-switch stub.
        let mut carve2 = Message::new(sdk::methods::region::CARVE);
        carve2.words[0] = 4096;
        carve2.words[1] = 4096;
        let sframe = match sys.invoke(package.region, &carve2) {
            Ok(r) => r.words[0] as u32,
            Err(e) => exit(&mut raw, 0x62 | (e & 0xF)),
        };
        let mut smap = Message::new(sdk::methods::aspace::MAP);
        smap.tag = smap.tag.with_caps(1);
        smap.words[0] = STUB_PAGE;
        smap.words[1] = 0b111; // R | W | X (no W^X yet; we write the stub)
        let _ = smap.set_descriptor(
            0,
            ipc::CapSlot::pack(sframe, ipc::Rights::READ.union(ipc::Rights::WRITE)),
        );
        if let Err(e) = sys.invoke(package.aspace, &smap) {
            exit(&mut raw, 0x63 | (e & 0xF));
        }
        // The guest stack pages and the stub page are mapped R|W|X in this AS
        // by the loops above, so every VA written here is valid: the Linux
        // startup layout (argv strings, envp/auxv block) and the RSP-switch
        // stub (mov rsp, rsp; mov rax, entry; jmp rax) go through the SDK's
        // raw VA writers instead of raw pointers (U4c).
        // Guest argv. Default: the freestanding demo reads argv[0].
        // busybox: argv[0]="busybox" selects applet-arg dispatch, and the
        // launcher's native argv[1..] become the applet and its arguments.
        let mut guest_argv: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::new();
        if busybox {
            // Multi-call invocation: argv[0] is the applet name (busybox
            // dispatches on basename(argv[0])), argv[1..] are its args.
            // The slices come from the frame-local copy, not the crafted
            // stack page (see `arg_buf` above).
            for i in 0..argn {
                guest_argv.push(&arg_buf[i][..arg_len[i]]);
            }
        } else {
            guest_argv.push(DEFAULT_ARGV0);
        }
        // Strings live in the lower half of the top stack page; AT_RANDOM
        // sits at +0x200, so keep the string area below it.
        let str_area = STACK_BASE + 0x100;
        let mut off = 0usize;
        let mut arg_ptrs: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        for a in &guest_argv {
            let p = str_area + off as u64;
            raw_copy_to_va(p, a);
            raw_copy_to_va(p + a.len() as u64, &[0u8]); // NUL terminator
            arg_ptrs.push(p);
            off += a.len() + 1;
        }
        debug_assert!(off <= 0x100, "guest argv strings overflow 0x100");
        let rnd = STACK_BASE + 0x200;
        for i in 0..16u64 {
            raw_copy_to_va(rnd + i, &[(0xA5 ^ i as u8)]);
        }
        // AT_PHDR/PHNUM/PHENT must describe ALL program headers (musl
        // walks them to find PT_TLS/PT_PHDR), not just the LOAD count.
        let rd16 = |o: usize| u16::from_le_bytes([elf[o], elf[o + 1]]) as u64;
        let rd64 = |o: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&elf[o..o + 8]);
            u64::from_le_bytes(b)
        };
        let e_phoff = rd64(32);
        let e_phentsize = rd16(54);
        let e_phnum = rd16(56);
        // Virtual address of the phdrs: the LOAD segment covering e_phoff.
        let mut phdr_va = 0u64;
        for i in 0..6 {
            if let Some(s) = sdk::elf::ElfImage::parse(elf)
                .ok()
                .and_then(|e| e.segment(i))
            {
                if e_phoff >= s.offset && e_phoff < s.offset + s.filesz {
                    phdr_va = s.vaddr + (e_phoff - s.offset);
                    break;
                }
            }
        }
        let auxv = [
            (3u64, phdr_va),  // AT_PHDR
            (4, e_phentsize), // AT_PHENT
            (5, e_phnum),     // AT_PHNUM
            (6, 4096),        // AT_PAGESZ
            (7, 0),           // AT_BASE (static)
            (9, entry),       // AT_ENTRY
            (16, 0),          // AT_HWCAP
            (25, rnd),        // AT_RANDOM
            (0, 0),           // AT_NULL
        ];
        // The initial block sits at the TOP of the stack with rsp pointing
        // at argc; the block runs upward, calls grow down into the pages.
        // Layout: argc, argv…, NULL, envp…, NULL, auxv pairs (the program
        // reads envp right after the argv NULL, then the auxv).
        let n = arg_ptrs.len();
        let n_qwords = 1 + (n + 1) + 1 + auxv.len() * 2;
        let rsp = STACK_BASE + STACK_PAGES * 4096 - (n_qwords as u64) * 8;
        let mut k = 0usize;
        let put = |at: usize, v: u64| raw_copy_to_va(rsp + (at as u64) * 8, &v.to_le_bytes());
        put(k, n as u64); // argc
        k += 1;
        for p in &arg_ptrs {
            put(k, *p);
            k += 1;
        }
        put(k, 0); // argv terminator
        k += 1;
        put(k, 0); // envp terminator (v0: empty environment)
        k += 1;
        for (a, v) in auxv {
            put(k, a);
            put(k + 1, v);
            k += 2;
        }
        // The stub: mov rsp, <rsp> (48 BC imm64); mov rax, entry
        // (48 B8 imm64); jmp rax (FF E0).
        raw_copy_to_va(STUB_PAGE, &[0x48, 0xBC]);
        raw_copy_to_va(STUB_PAGE + 2, &rsp.to_le_bytes());
        raw_copy_to_va(STUB_PAGE + 10, &[0x48, 0xB8]);
        raw_copy_to_va(STUB_PAGE + 12, &entry.to_le_bytes());
        raw_copy_to_va(STUB_PAGE + 20, &[0xFF, 0xE0]);
    }
    let child = {
        let mut sys = Syscalls::new(&mut raw);
        let mut m = Message::new(sdk::methods::thread::THREAD_CREATE);
        m.words[0] = STUB_PAGE; // run the RSP-switch stub first, not entry
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
    // Emulated stdout is buffered and flushed after each reply (never a
    // nested send while a foreign reply is pending).
    let (region_h, aspace_h) = (package.region, package.aspace);
    let mut mmap_bump = MMAP_VA_BASE;
    let mut brk_cur = BRK_VA_BASE;
    let mut dents_cookie = [0u64; 16];
    let mut outbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
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
                if let Some(h) = out {
                    let mut b = [b'#'; 17];
                    for i in 0..16 {
                        let nib = ((num >> ((15 - i) * 4)) & 0xF) as u8;
                        b[1 + i] = b"0123456789abcdef"[nib as usize];
                    }
                    let mut sys = Syscalls::new(&mut raw);
                    let mut m = Message::new(sdk::methods::console::WRITE);
                    m.words = sdk::methods::pack_console_text(&b);
                    let _ = sys.send(h, &m);
                }
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
                    let mut host = Emu {
                        raw: &mut raw,
                        child,
                        buf: &mut outbuf,
                        vfs: vfs.as_mut(),
                        region: region_h,
                        aspace: aspace_h,
                        mmap_bump: &mut mmap_bump,
                        brk_cur: &mut brk_cur,
                        dents_cookie: &mut dents_cookie,
                    };
                    personality::foreign::dispatch(num, args, &mut host)
                };
                match action {
                    personality::foreign::Action::Return(v) => {
                        let mut rep = Message::new(ipc::labels::kernel::FOREIGN_SYSCALL);
                        rep.words[0] = v as u64;
                        let mut sys = Syscalls::new(&mut raw);
                        let _ = sys.reply(&rep);
                        // No foreign reply is pending now, so flush the emulated
                        // stdout to the console.
                        if let Some(h) = out {
                            for chunk in outbuf.chunks(sdk::methods::console::TEXT_BYTES) {
                                let mut m = Message::new(sdk::methods::console::WRITE);
                                m.words = sdk::methods::pack_console_text(chunk);
                                let mut sys = Syscalls::new(&mut raw);
                                let _ = sys.send(h, &m);
                            }
                        }
                        outbuf.clear();
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
// jumps here). The v0.2 crafted stack carries argc/argv/envp at [rsp-8/-16/-24]
// (sdk::args); capture them before touching rsp, exactly as other SDK bins do.
global_asm!(
    ".global _start",
    "_start:",
    "mov rdi, [rsp - 8]",
    "mov rsi, [rsp - 16]",
    "mov rdx, [rsp - 24]",
    "and rsp, -16",
    "call {main}",
    main = sym linrun_main,
);

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Exit rather than spin: a panic in the emulator must surface as a process
    // failure (the launcher reaps a nonzero status), not a hung boot.
    exit(&mut X86_64Syscalls, 0x0BAD_0041)
}
