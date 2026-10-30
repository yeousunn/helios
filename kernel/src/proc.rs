//! Process registry: per-process capability tables (ADR-011 §1).
//!
//! The registry is a const-initialized, preallocated static — spawning a
//! process never builds large temporaries on the stack (kernel boot paths
//! must not blow the stack).
#![forbid(unsafe_code)]

use caps::{CapError, CapTable, Capability, ObjId, SlotIdx};
use spin::Mutex;

const MAX_PROCESSES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcError {
    TableFull,
    NoSuchProcess,
    Cap(CapError),
    BadHandle,
}

impl From<CapError> for ProcError {
    fn from(e: CapError) -> Self {
        ProcError::Cap(e)
    }
}

pub type ProcResult<T> = Result<T, ProcError>;

/// Kernel-side process id == registry index + 1 (0 = none).
pub type ProcessId = ObjId;

/// Preallocated registry state (const-initialized in the static).
struct RegistryInner {
    used: [bool; MAX_PROCESSES],
    tables: [CapTable; MAX_PROCESSES],
}

impl RegistryInner {
    const fn new() -> Self {
        RegistryInner {
            used: [false; MAX_PROCESSES],
            tables: [const { CapTable::empty() }; MAX_PROCESSES],
        }
    }
}

static REGISTRY: Mutex<RegistryInner> = Mutex::new(RegistryInner::new());

/// Create a process with an empty capability table.
pub fn create() -> ProcResult<ProcessId> {
    let mut guard = REGISTRY.lock();
    let idx = guard
        .used
        .iter()
        .position(|u| !u)
        .ok_or(ProcError::TableFull)?;
    guard.used[idx] = true;
    guard.tables[idx] = CapTable::empty();
    Ok(ObjId(idx as u64 + 1))
}

/// Destroy a process and drop its whole table.
pub fn destroy(pid: ProcessId) -> ProcResult<()> {
    let mut guard = REGISTRY.lock();
    let idx = (pid.0 as usize)
        .checked_sub(1)
        .ok_or(ProcError::NoSuchProcess)?;
    if idx >= MAX_PROCESSES || !guard.used[idx] {
        return Err(ProcError::NoSuchProcess);
    }
    guard.used[idx] = false;
    guard.tables[idx] = CapTable::empty();
    Ok(())
}

fn with_table<T>(pid: ProcessId, f: impl FnOnce(&mut CapTable) -> ProcResult<T>) -> ProcResult<T> {
    let mut guard = REGISTRY.lock();
    let idx = (pid.0 as usize)
        .checked_sub(1)
        .ok_or(ProcError::NoSuchProcess)?;
    if idx >= MAX_PROCESSES || !guard.used[idx] {
        return Err(ProcError::NoSuchProcess);
    }
    f(&mut guard.tables[idx])
}

fn slot_of(handle: u32) -> ProcResult<SlotIdx> {
    if handle == 0 || handle == u32::MAX {
        return Err(ProcError::BadHandle);
    }
    Ok((handle - 1) as SlotIdx)
}

/// Read the capability behind `handle` (kernel use only).
pub fn get_cap(pid: ProcessId, handle: u32) -> ProcResult<Capability> {
    with_table(pid, |t| {
        let slot = slot_of(handle)?;
        t.get(slot).map_err(ProcError::from)
    })
}

/// Install a fresh capability at the first free slot; returns the handle.
pub fn install_cap(pid: ProcessId, cap: Capability) -> ProcResult<u32> {
    with_table(pid, |t| {
        let slot = t.insert(cap)?;
        Ok(slot as u32 + 1)
    })
}

/// Install at an exact slot (bootstrap endpoint → handle 1 = slot 0, ADR-009).
pub fn install_cap_at(pid: ProcessId, slot: SlotIdx, cap: Capability) -> ProcResult<u32> {
    with_table(pid, |t| {
        t.insert_at(slot, cap)?;
        Ok(slot as u32 + 1)
    })
}

/// Derive a child cap within the same process (`cap_mint`).
/// `dst_handle` of `ipc::FIRST_FREE_SLOT` allocates; anything else targets
/// that exact slot (installed at `dst_handle - 1`).
pub fn mint(
    pid: ProcessId,
    parent_handle: u32,
    rights: ipc::Rights,
    dst_handle: u32,
) -> ProcResult<u32> {
    with_table(pid, |t| {
        let parent_slot = slot_of(parent_handle)?;
        if dst_handle == ipc::FIRST_FREE_SLOT {
            let slot = t.mint_here(parent_slot, rights)?;
            return Ok(slot as u32 + 1);
        }
        let dst_slot = slot_of(dst_handle)?;
        let parent = t.get(parent_slot)?;
        if !parent.rights.contains(ipc::Rights::GRANT) {
            return Err(ProcError::Cap(CapError::MissingGrantRight));
        }
        if !parent.rights.contains(rights) {
            return Err(ProcError::Cap(CapError::RightsNotSubset));
        }
        t.insert_at(
            dst_slot,
            Capability {
                obj: parent.obj,
                typ: parent.typ,
                rights,
            },
        )?;
        Ok(dst_handle)
    })
}

/// Revoke: mode 0 = REVOKE_DERIVED (keep cap), 1 = DELETE (ADR-005 §5).
/// Returns the number of caps removed (excluding the cap on DERIVED).
pub fn revoke(pid: ProcessId, handle: u32, mode: u64) -> ProcResult<usize> {
    with_table(pid, |t| {
        let slot = slot_of(handle)?;
        match mode {
            0 => t.revoke_derived(slot).map_err(ProcError::from),
            1 => t.delete_cascade(slot).map_err(ProcError::from),
            _ => Err(ProcError::Cap(CapError::BadSlot)),
        }
    })
}

/// Remove a single cap (internal; e.g. reply-cap cleanup paths).
pub fn remove_cap(pid: ProcessId, handle: u32) -> ProcResult<()> {
    with_table(pid, |t| {
        t.remove(slot_of(handle)?)?;
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    let mut guard = REGISTRY.lock();
    for i in 0..MAX_PROCESSES {
        guard.used[i] = false;
        guard.tables[i] = CapTable::empty();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caps::ObjType;

    fn ep_cap(id: u64, rights: ipc::Rights) -> Capability {
        Capability {
            obj: ObjId(id),
            typ: ObjType::Endpoint,
            rights,
        }
    }

    #[test]
    fn create_install_mint_revoke_cycle() {
        reset_for_test();
        let pid = create().unwrap();

        // Bootstrap install: exact slot 0 → handle 1 (ADR-009).
        let h1 = install_cap_at(
            pid,
            0,
            ep_cap(7, ipc::Rights::SEND.union(ipc::Rights::GRANT)),
        )
        .unwrap();
        assert_eq!(h1, 1);

        // First-free install.
        let h2 = install_cap(pid, ep_cap(8, ipc::Rights::RECV)).unwrap();
        assert_eq!(h2, 2);
        assert_eq!(get_cap(pid, h2).unwrap().obj, ObjId(8));

        // Mint child at first-free slot.
        let h3 = mint(pid, h1, ipc::Rights::SEND, ipc::FIRST_FREE_SLOT).unwrap();
        assert_eq!(get_cap(pid, h3).unwrap().rights, ipc::Rights::SEND);

        // Revoke derived keeps the parent.
        assert_eq!(revoke(pid, h1, 0).unwrap(), 1);
        assert!(get_cap(pid, h1).is_ok());
        assert!(get_cap(pid, h3).is_err());

        // Delete removes the cap too.
        assert_eq!(revoke(pid, h1, 1).unwrap(), 1);
        assert!(get_cap(pid, h1).is_err());

        destroy(pid).unwrap();
        assert!(get_cap(pid, h1).is_err(), "destroyed process has no caps");
    }

    #[test]
    fn handle_zero_and_sentinel_are_rejected() {
        reset_for_test();
        let pid = create().unwrap();
        assert_eq!(get_cap(pid, 0), Err(ProcError::BadHandle));
        assert_eq!(
            mint(pid, ipc::FIRST_FREE_SLOT, ipc::Rights::SEND, 0xFFFF_FFFF),
            Err(ProcError::BadHandle)
        );
        assert_eq!(destroy(ObjId(999)), Err(ProcError::NoSuchProcess));
    }
}
