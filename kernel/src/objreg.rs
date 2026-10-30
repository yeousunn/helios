//! Kernel object registry: ownership, liveness, death cleanup (ADR-026).
#![forbid(unsafe_code)]

use caps::{ObjId, ObjType};
use spin::Mutex;

/// Kernel-side process id (= proc registry index + 1).
pub type ProcessId = ObjId;

const MAX_OBJECTS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub obj: ObjId,
    pub typ: ObjType,
    pub owner: ProcessId,
    pub epoch: u32,
    pub alive: bool,
}

struct Registry {
    entries: [Option<Entry>; MAX_OBJECTS],
}

static REGISTRY: Mutex<Option<Registry>> = Mutex::new(None);

fn with_reg<T>(f: impl FnOnce(&mut Registry) -> T) -> Option<T> {
    let mut guard = REGISTRY.lock();
    guard.as_mut().map(f)
}

/// Register a freshly created kernel object. Idempotent per (obj, typ).
pub fn register(obj: ObjId, typ: ObjType, owner: ProcessId) {
    with_reg(|r| {
        if r.entries
            .iter()
            .flatten()
            .any(|e| e.obj == obj && e.typ == typ)
        {
            return;
        }
        for slot in r.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(Entry {
                    obj,
                    typ,
                    owner,
                    epoch: 0,
                    alive: true,
                });
                return;
            }
        }
        crate::kwarn!("objreg full: {} unregistered", obj.0);
    });
}

/// Remove a registration (object genuinely destroyed without owner death).
pub fn unregister(obj: ObjId) {
    with_reg(|r| {
        for slot in r.entries.iter_mut() {
            if let Some(e) = slot {
                if e.obj == obj {
                    *slot = None;
                    return;
                }
            }
        }
    });
}

/// Is the object alive? Unregistered ids count as alive (kernel-reserved
/// ids like the debug endpoint never register).
pub fn is_alive(obj: ObjId) -> bool {
    with_reg(|r| {
        r.entries
            .iter()
            .flatten()
            .find(|e| e.obj == obj)
            .map(|e| e.alive)
            .unwrap_or(true)
    })
    .unwrap_or(true)
}

/// Current epoch (0 if unregistered).
pub fn epoch(obj: ObjId) -> u32 {
    with_reg(|r| {
        r.entries
            .iter()
            .flatten()
            .find(|e| e.obj == obj)
            .map(|e| e.epoch)
            .unwrap_or(0)
    })
    .unwrap_or(0)
}

/// Mark every object owned by `pid` dead (epoch bump) and return the
/// (typ, obj) list for teardown by the caller (sys_exit).
pub fn retire_owner(pid: ProcessId) -> [(ObjType, ObjId); MAX_OBJECTS] {
    let mut out = [(ObjType::Factory, ObjId(0)); MAX_OBJECTS];
    let mut n = 0;
    with_reg(|r| {
        for slot in r.entries.iter_mut().flatten() {
            if slot.owner == pid && slot.alive {
                slot.alive = false;
                slot.epoch = slot.epoch.wrapping_add(1);
                if n < MAX_OBJECTS {
                    out[n] = (slot.typ, slot.obj);
                    n += 1;
                }
            }
        }
    });
    out
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    *REGISTRY.lock() = Some(Registry {
        entries: [const { None }; MAX_OBJECTS],
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        reset_for_test();
    }

    #[test]
    fn register_liveness_retire() {
        setup();
        let pid = ObjId(1);
        let ep = ObjId(10);
        let n = ObjId(11);
        register(ep, ObjType::Endpoint, pid);
        register(n, ObjType::Notification, pid);
        assert!(is_alive(ep));
        assert_eq!(epoch(ep), 0);

        let dead = retire_owner(pid);
        assert_eq!(dead[0], (ObjType::Endpoint, ep));
        assert_eq!(dead[1], (ObjType::Notification, n));
        assert!(!is_alive(ep), "retired object is dead");
        assert_eq!(epoch(ep), 1, "epoch bumped on retire");
        assert!(!is_alive(n));

        // Unregistered ids are treated as alive (kernel-reserved objects).
        assert!(is_alive(ObjId(0xD1)));
        // Double retire: nothing left.
        let dead2 = retire_owner(pid);
        assert_eq!(dead2[0].1, ObjId(0));
    }

    #[test]
    fn unregister_removes_entry() {
        setup();
        let ep = ObjId(20);
        register(ep, ObjType::Endpoint, ObjId(2));
        unregister(ep);
        assert!(is_alive(ep), "unregistered = no liveness tracking");
        // Re-register works.
        register(ep, ObjType::Endpoint, ObjId(3));
        assert!(is_alive(ep));
    }

    #[test]
    fn other_owners_survive_retire() {
        setup();
        let a = ObjId(1);
        let b = ObjId(2);
        register(ObjId(30), ObjType::Endpoint, a);
        register(ObjId(31), ObjType::Endpoint, b);
        retire_owner(a);
        assert!(!is_alive(ObjId(30)));
        assert!(is_alive(ObjId(31)), "other owners unaffected");
    }
}
