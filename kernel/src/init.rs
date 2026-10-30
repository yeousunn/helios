//! Init bootstrap (ADR-018, syscall-abi §8): kernel main, BootInfo writer,
//! Region registry, and the debug endpoint special case.
#![forbid(unsafe_code)]

use crate::frame::{self, PhysAddr};
use crate::proc::{self, ProcessId};
use crate::sched::{self, ObjRef, ThreadId};
use caps::{Capability, ObjId, ObjType, Rights};
use ipc::Message;
use spin::Mutex;

/// Reserved kernel object id for the debug (serial console) endpoint.
pub const DEBUG_EP_ID: u64 = 0xD1;

/// BootInfo magic: "HELI" little-endian.
pub const BOOTINFO_MAGIC: u32 = 0x4845_4C49;
pub const BOOTINFO_VERSION: u32 = 0;

/// One usable physical memory region handed to init.
#[derive(Clone, Copy, Debug)]
pub struct BootRegion {
    pub base: PhysAddr,
    pub len: u64,
}

/// BootInfo v0 values, composed by [`start`] and serialized by
/// [`write_bootinfo`] (syscall-abi §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInfoV0 {
    pub debug_ep: u32,
    pub factory: u32,
    /// ADR-023 §1: the caller's own AS cap handle (0 = none). Occupies the
    /// formerly-reserved u32 at offset 20.
    pub self_as: u32,
    /// (handle, base, len) triples, in grant order.
    pub regions: [(u32, u64, u64); MAX_BOOT_REGIONS],
    pub region_count: u32,
}

pub const MAX_BOOT_REGIONS: usize = 8;

/// Serialize BootInfo v0 into `buf` (little-endian, repr(C) layout):
/// ```text
/// u32 magic; u32 version; u32 debug_ep; u32 factory;
/// u32 region_count; u32 reserved;
/// then region_count × { u32 handle; u32 reserved; u64 base; u64 len }
/// ```
/// Returns the number of bytes written. Regions beyond `MAX_BOOT_REGIONS`
/// are dropped (truncated to region_count).
pub fn write_bootinfo(buf: &mut [u8], info: &BootInfoV0) -> usize {
    let count = (info.region_count as usize).min(MAX_BOOT_REGIONS);
    let need = 24 + count * 24;
    if buf.len() < need {
        return 0;
    }
    let mut w = |off: usize, v: u64, len: usize| {
        for i in 0..len {
            buf[off + i] = ((v >> (i * 8)) & 0xFF) as u8;
        }
    };
    w(0, BOOTINFO_MAGIC as u64, 4);
    w(4, BOOTINFO_VERSION as u64, 4);
    w(8, info.debug_ep as u64, 4);
    w(12, info.factory as u64, 4);
    w(16, count as u64, 4);
    w(20, info.self_as as u64, 4);
    for (i, &(handle, base, len)) in info.regions[..count].iter().enumerate() {
        let off = 24 + i * 24;
        w(off, handle as u64, 4);
        w(off + 4, 0, 4);
        w(off + 8, base, 8);
        w(off + 16, len, 8);
    }
    need
}

/// Result of the init bootstrap: everything the arch entry needs to enter
/// userspace.
#[derive(Clone, Copy, Debug)]
pub struct InitLaunch {
    pub pid: ProcessId,
    pub thread: ThreadId,
    pub bootinfo: BootInfoV0,
}

/// The kernel main: arch code calls this after `early_init`, `frame::init`,
/// and backend/context registrations. Idempotency is enforced (one init).
pub fn start(regions: &[BootRegion]) -> Result<InitLaunch, &'static str> {
    if regions.is_empty() {
        return Err("no boot regions for init");
    }
    if regions.len() > MAX_BOOT_REGIONS {
        return Err("too many boot regions");
    }
    let pid = proc::create().map_err(|_| "cannot create init process")?;

    // Factory (full rights) at first free handle.
    let factory = proc::install_cap(
        pid,
        Capability {
            obj: ObjId(1),
            typ: ObjType::Factory,
            rights: Rights::ALL,
        },
    )
    .map_err(|_| "cannot grant Factory")?;

    // Debug endpoint (reserved id) with SEND only — init may write, never read.
    let debug_ep = proc::install_cap(
        pid,
        Capability {
            obj: ObjId(DEBUG_EP_ID),
            typ: ObjType::Endpoint,
            rights: Rights::SEND,
        },
    )
    .map_err(|_| "cannot grant debug EP")?;

    // Region caps over the boot regions.
    let mut info = BootInfoV0 {
        debug_ep,
        factory,
        self_as: 0,
        regions: [(0, 0, 0); MAX_BOOT_REGIONS],
        region_count: regions.len() as u32,
    };
    for (i, r) in regions.iter().enumerate() {
        let region_id = 0x100 + i as u64;
        let handle = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(region_id),
                typ: ObjType::Region,
                rights: Rights::default(), // carve-only; rights via Region methods
            },
        )
        .map_err(|_| "cannot grant Region")?;
        info.regions[i] = (handle, r.base.as_u64(), r.len);
        REGIONS.lock().add(region_id, r.base.as_u64(), r.len);
    }

    // ADR-023 §1: grant init its own AS (the default AS) so it can map
    // heaps/stacks/child images. Ensure the default AS exists.
    let _ = crate::aspace::init_default();
    let self_as = proc::install_cap(
        pid,
        Capability {
            obj: crate::aspace::DEFAULT_AS,
            typ: ObjType::AddressSpace,
            rights: Rights::MAP.union(Rights::GRANT),
        },
    )
    .map_err(|_| "cannot grant self-AS")?;
    proc::set_as(pid, crate::aspace::DEFAULT_AS).map_err(|_| "cannot link init AS")?;
    info.self_as = self_as;

    let thread = sched::spawn(ObjRef(pid.0), sched::DEFAULT_PRIORITY)
        .map_err(|_| "cannot spawn init thread")?;

    Ok(InitLaunch {
        pid,
        thread,
        bootinfo: info,
    })
}

/// Region registry: region id → base/len/next carve offset (ADR-018 §3).
struct RegionRegistry {
    ids: [u64; MAX_BOOT_REGIONS],
    base: [u64; MAX_BOOT_REGIONS],
    len: [u64; MAX_BOOT_REGIONS],
    next: [u64; MAX_BOOT_REGIONS],
}

impl RegionRegistry {
    const fn new() -> Self {
        RegionRegistry {
            ids: [0; MAX_BOOT_REGIONS],
            base: [0; MAX_BOOT_REGIONS],
            len: [0; MAX_BOOT_REGIONS],
            next: [0; MAX_BOOT_REGIONS],
        }
    }

    fn add(&mut self, id: u64, base: u64, len: u64) {
        for i in 0..MAX_BOOT_REGIONS {
            if self.ids[i] == 0 {
                self.ids[i] = id;
                self.base[i] = base;
                self.len[i] = len;
                self.next[i] = 0;
                return;
            }
        }
    }

    fn remaining(&self, id: u64) -> Option<(u64, u64)> {
        let i = self.ids.iter().position(|x| *x == id)?;
        Some((self.base[i] + self.next[i], self.len[i] - self.next[i]))
    }

    fn dedicate(&mut self, id: u64) -> bool {
        match self.ids.iter().position(|x| *x == id) {
            Some(i) => {
                // Mark fully consumed: all remaining space becomes the pool.
                self.next[i] = self.len[i];
                true
            }
            None => false,
        }
    }

    fn carve(&mut self, id: u64, bytes: u64) -> Option<PhysAddr> {
        let i = self.ids.iter().position(|x| *x == id)?;
        let frame = frame::FRAME_SIZE as u64;
        if bytes == 0 || !bytes.is_multiple_of(frame) {
            return None;
        }
        let start = self.base[i] + self.next[i];
        let end = self.base[i] + self.len[i];
        if start + bytes > end {
            return None;
        }
        self.next[i] += bytes;
        Some(PhysAddr::new(start))
    }
}

static REGIONS: Mutex<RegionRegistry> = Mutex::new(RegionRegistry::new());

/// Handle `Region::CARVE` (invoke id 1) for a Region cap.
/// w0 = size in bytes (page multiple), w1 = alignment (v0: page-aligned
/// only). Installs a Frame cap (R|W|GRANT) in the caller's table and returns
/// the handle in w0.
pub fn region_carve(pid: ProcessId, region: ObjId, w0: u64, w1: u64) -> Result<u32, i32> {
    if w1 != 0 && w1 != frame::FRAME_SIZE as u64 {
        return Err(ipc::status::EBADARG);
    }
    if w0 == 0 || !w0.is_multiple_of(frame::FRAME_SIZE as u64) {
        return Err(ipc::status::EBADARG);
    }
    let addr = REGIONS
        .lock()
        .carve(region.0, w0)
        .ok_or(ipc::status::ENOMEM)?;
    // Reserve the frame range with the frame allocator so nothing double-
    // allocates it (the boot regions must be registered with frame::init as
    // managed regions by arch code).
    let frames = (w0 / frame::FRAME_SIZE as u64) as usize;
    if frame::alloc_contiguous(frames).is_none() {
        return Err(ipc::status::ENOMEM);
    }
    proc::install_cap(
        pid,
        Capability {
            obj: ObjId(addr.as_u64()),
            typ: ObjType::Frame,
            rights: Rights::READ
                .union(Rights::WRITE)
                .union(Rights::EXEC)
                .union(Rights::GRANT),
        },
    )
    .map_err(|_| ipc::status::ENOMEM)
}

/// `AddressSpace::SET_FAULT_POOL` (ADR-018 §3 + ADR-021 v0): dedicate the
/// Region cap's remaining space as the (global, v0) fault pool. Further
/// CARVE on that region returns ENOMEM.
pub fn region_dedicate_as_pool(region: ObjId) -> Result<(PhysAddr, u64), i32> {
    let mut r = REGIONS.lock();
    let (base, len) = r.remaining(region.0).ok_or(ipc::status::EBADCAP)?;
    if len == 0 {
        return Err(ipc::status::ENOMEM);
    }
    if !r.dedicate(region.0) {
        return Err(ipc::status::EBADCAP);
    }
    Ok((PhysAddr::new(base), len))
}

/// Debug endpoint fast path (ADR-018 §4): log payload words, no delivery.
pub fn debug_ep_send(msg: &Message) {
    crate::kinfo!(
        "userspace[debug]: tag={:#x} w=[{:#x} {:#x} {:#x} {:#x}]",
        msg.tag.0,
        msg.words[0],
        msg.words[1],
        msg.words[2],
        msg.words[3]
    );
}

#[cfg(test)]
pub(crate) fn register_region_for_test(id: u64, base: u64, len: u64) {
    REGIONS.lock().add(id, base, len);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame;
    use crate::syscall;

    struct TestCtx;
    impl crate::sched::ContextBackend for TestCtx {
        fn switch(&self, _f: ThreadId, _t: ThreadId) {}
        fn start_first(&self, _t: ThreadId) {}
    }

    struct BootFactory;
    impl crate::aspace::BackendFactory for BootFactory {
        fn create(&self, _id: u64) -> Option<&'static dyn crate::aspace::PagingBackend> {
            Some(&BootBackend)
        }
    }

    struct BootBackend;
    impl crate::aspace::PagingBackend for BootBackend {
        fn map_page(&self, _v: crate::aspace::Vaddr, _p: PhysAddr, _f: crate::aspace::MapFlags) {}
        fn unmap_page(&self, _v: crate::aspace::Vaddr) {}
        fn protect_page(&self, _v: crate::aspace::Vaddr, _f: crate::aspace::MapFlags) {}
    }

    fn setup() {
        crate::aspace::set_backend_factory(&BootFactory);
        proc::reset_for_test();
        crate::endpoint::reset_engine_for_test();
        crate::notification::reset_for_test();
        syscall::reset_reply_for_test();
        *sched::SCHED.lock() = None;
        sched::set_context_backend(&TestCtx);
        let _ = sched::init();
        *REGIONS.lock() = RegionRegistry::new();
        // Frame allocator: 16 frames at 0x10_0000 (region module tests may
        // have consumed init; frame::init rejects re-init, so use whatever
        // is free — the carve path checks availability dynamically).
        let r =
            frame::Region::new(PhysAddr::new(0x10_0000), 16 * frame::FRAME_SIZE as u64).unwrap();
        let _ = frame::init(&[r]);
    }

    #[test]
    fn bootinfo_writer_layout() {
        let mut buf = [0u8; 256];
        let mut regions = [(0u32, 0u64, 0u64); MAX_BOOT_REGIONS];
        regions[0] = (4, 0x100000, 0x40000);
        regions[1] = (5, 0x200000, 0x80000);
        let info = BootInfoV0 {
            debug_ep: 2,
            factory: 3,
            self_as: 9,
            regions,
            region_count: 2,
        };
        let n = write_bootinfo(&mut buf, &info);
        assert_eq!(n, 24 + 2 * 24);
        let rd = |o: usize| -> u64 {
            u64::from_le_bytes(buf[o..o + 8].try_into().unwrap())
                & ((1u128 << (8 * 4)) as u64 - 1)
                & 0xFFFF_FFFF
        };
        let rd32 = |o: usize| -> u32 { u32::from_le_bytes(buf[o..o + 4].try_into().unwrap()) };
        assert_eq!(rd32(0), BOOTINFO_MAGIC);
        assert_eq!(rd32(4), 0);
        assert_eq!(rd32(8), 2);
        assert_eq!(rd32(12), 3);
        assert_eq!(rd32(16), 2);
        assert_eq!(rd32(20), 9, "self_as at offset 20 (ADR-023)");
        assert_eq!(rd32(24), 4);
        // base/len are u64 fields.
        let base0 = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let len0 = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        assert_eq!(base0, 0x100000);
        assert_eq!(len0, 0x40000);
        let _ = rd(0);
    }

    #[test]
    fn bootinfo_truncates_when_buffer_too_small() {
        let mut buf = [0u8; 10];
        let info = BootInfoV0 {
            debug_ep: 0,
            factory: 0,
            self_as: 0,
            regions: [(0, 0, 0); MAX_BOOT_REGIONS],
            region_count: 0,
        };
        assert_eq!(write_bootinfo(&mut buf, &info), 0);
    }

    #[test]
    fn init_start_grants_and_spawns() {
        setup();
        let launch = start(&[BootRegion {
            base: PhysAddr::new(0x10_0000),
            len: 0x40000,
        }])
        .unwrap();
        assert_eq!(launch.bootinfo.region_count, 1);
        // Factory has ALL rights.
        let f = proc::get_cap(launch.pid, launch.bootinfo.factory).unwrap();
        assert_eq!(f.typ, ObjType::Factory);
        assert!(f.rights.contains(Rights::ALL));
        // Debug EP is SEND-only on the reserved id.
        let d = proc::get_cap(launch.pid, launch.bootinfo.debug_ep).unwrap();
        assert_eq!(d.typ, ObjType::Endpoint);
        assert_eq!(d.obj, ObjId(DEBUG_EP_ID));
        assert_eq!(d.rights, Rights::SEND);
        // Region cap registered.
        let (h, base, len) = launch.bootinfo.regions[0];
        let rc = proc::get_cap(launch.pid, h).unwrap();
        assert_eq!(rc.typ, ObjType::Region);
        assert_eq!(base, 0x10_0000);
        assert_eq!(len, 0x40000);
        // Thread spawned.
        assert!(sched::get(launch.thread).is_ok());
    }

    #[test]
    fn region_carve_and_frame_cap() {
        setup();
        let launch = start(&[BootRegion {
            base: PhysAddr::new(0x10_0000),
            len: 0x40000,
        }])
        .unwrap();
        let (_, _, _) = launch.bootinfo.regions[0];

        // Carve 2 frames.
        let fh = region_carve(launch.pid, ObjId(0x100), 2 * frame::FRAME_SIZE as u64, 0).unwrap();
        let fc = proc::get_cap(launch.pid, fh).unwrap();
        assert_eq!(fc.typ, ObjType::Frame);
        assert!(fc.rights.contains(Rights::READ) && fc.rights.contains(Rights::WRITE));

        // Second carve continues after the first.
        let fh2 = region_carve(launch.pid, ObjId(0x100), frame::FRAME_SIZE as u64, 0).unwrap();
        let a1 = proc::get_cap(launch.pid, fh).unwrap().obj.0;
        let a2 = proc::get_cap(launch.pid, fh2).unwrap().obj.0;
        assert_eq!(a2 - a1, 2 * frame::FRAME_SIZE as u64);

        // Unaligned size rejected.
        assert_eq!(
            region_carve(launch.pid, ObjId(0x100), 100, 0),
            Err(ipc::status::EBADARG)
        );
        // Non-page alignment requested → EBADARG.
        assert_eq!(
            region_carve(launch.pid, ObjId(0x100), frame::FRAME_SIZE as u64, 8),
            Err(ipc::status::EBADARG)
        );
        // Exhaustion → ENOMEM (region is 0x40000 = 64 frames; 3 carved).
        let mut carved: std::vec::Vec<u64> = std::vec::Vec::new();
        loop {
            match region_carve(launch.pid, ObjId(0x100), frame::FRAME_SIZE as u64, 0) {
                Ok(h) => carved.push(proc::get_cap(launch.pid, h).unwrap().obj.0),
                Err(ipc::status::ENOMEM) => break,
                Err(e) => panic!("unexpected {e}"),
            }
        }
        // Leave the allocator fully free for subsequent tests.
        carved.push(a1);
        carved.push(a2);
        for addr in carved {
            let _ = frame::free(PhysAddr::new(addr));
        }
    }
}
