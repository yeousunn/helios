//! Commutativity classifications for scaling (bet B1, B8)
//!
//! Commutativity determines whether two operations can be executed in parallel
//! on different NUMA nodes (CNR logs) or must be serialized. This is critical
//! for the NR (Node Replication) wrapper around the sequential kernel core.

use core::fmt;

/// Commutativity classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Commutativity {
    /// Operations on different resources always commute (e.g., map/unmap on disjoint ranges)
    Commutes,
    /// Operations on disjoint resources commute; on overlapping resources they conflict
    /// (e.g., MAP/UNMAP on same range conflicts, on different ranges commutes)
    CommutesDisjointRanges,
    /// Commutativity depends on the specific method/arguments (for INVOKE)
    DependsOnMethod,
    /// Operations never commute (e.g., revoke, fork, destroy)
    Conflicts,
}

impl Commutativity {
    /// Check if two operations of this commutativity class can run in parallel
    /// given their resource arguments.
    pub fn can_parallelize(
        self,
        resource_a: Option<ResourceKey>,
        resource_b: Option<ResourceKey>,
    ) -> bool {
        match self {
            Commutativity::Commutes => true,
            Commutativity::CommutesDisjointRanges => {
                match (resource_a, resource_b) {
                    (Some(a), Some(b)) => a.is_disjoint_from(&b),
                    _ => true, // If we can't determine resources, assume they might conflict
                }
            }
            Commutativity::DependsOnMethod => true, // Caller must check specific method
            Commutativity::Conflicts => false,
        }
    }
}

impl fmt::Display for Commutativity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Commutativity::Commutes => write!(f, "Commutes"),
            Commutativity::CommutesDisjointRanges => write!(f, "CommutesDisjointRanges"),
            Commutativity::DependsOnMethod => write!(f, "DependsOnMethod"),
            Commutativity::Conflicts => write!(f, "Conflicts"),
        }
    }
}

/// Resource key for commutativity checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKey {
    /// Virtual address range: (base, pages)
    VaddrRange { base: u64, pages: u64 },
    /// Capability slot: (process_id, slot)
    CapSlot { pid: u64, slot: u32 },
    /// Object ID: (object_type, object_id)
    ObjId { obj_type: u8, obj_id: u64 },
    /// Global kernel resource (e.g., root CNode, scheduler)
    Global,
}

impl ResourceKey {
    /// Check if two resource keys are disjoint
    pub fn is_disjoint_from(&self, other: &ResourceKey) -> bool {
        match (self, other) {
            (
                ResourceKey::VaddrRange {
                    base: a_base,
                    pages: a_pages,
                },
                ResourceKey::VaddrRange {
                    base: b_base,
                    pages: b_pages,
                },
            ) => {
                let a_end = *a_base + *a_pages * 4096;
                let b_end = *b_base + *b_pages * 4096;
                a_end <= *b_base || b_end <= *a_base
            }
            (
                ResourceKey::CapSlot {
                    pid: a_pid,
                    slot: a_slot,
                },
                ResourceKey::CapSlot {
                    pid: b_pid,
                    slot: b_slot,
                },
            ) => *a_pid != *b_pid || *a_slot != *b_slot,
            (
                ResourceKey::ObjId {
                    obj_type: a_type,
                    obj_id: a_id,
                },
                ResourceKey::ObjId {
                    obj_type: b_type,
                    obj_id: b_id,
                },
            ) => *a_type != *b_type || *a_id != *b_id,
            (ResourceKey::Global, ResourceKey::Global) => false,
            (ResourceKey::Global, _) | (_, ResourceKey::Global) => false,
            _ => true, // Different resource types are disjoint
        }
    }
}

/// Commutativity specification for a syscall or invoke method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommutativitySpec {
    /// Base commutativity class
    pub class: Commutativity,
    /// For CommutesDisjointRanges: how to extract the resource key from arguments
    pub resource_extractor: ResourceExtractor,
    /// Additional notes
    pub notes: &'static str,
}

/// How to extract a resource key from syscall/invoke arguments
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceExtractor {
    /// No resource key (for Commutes or Conflicts)
    None,
    /// Virtual address range from w0 (vaddr) and w1 (pages)
    VaddrRange { vaddr_arg: usize, pages_arg: usize },
    /// Capability slot from cap argument
    CapSlot,
    /// Object ID from capability's obj_id
    ObjId,
    /// Global resource
    Global,
    /// Method-dependent (for INVOKE)
    MethodDependent,
}

/// Standard commutativity specs for syscalls
pub mod syscall_commutativity {
    use super::{Commutativity, CommutativitySpec, ResourceExtractor};

    pub const YIELD: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::None,
        notes: "YIELD only affects the calling thread's scheduling state",
    };

    pub const SEND: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes: "SEND to different endpoints commutes. SEND to same endpoint serializes on the endpoint's mailbox lock.",
    };

    pub const CALL: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes: "CALL to different endpoints commutes. Same endpoint serializes.",
    };

    pub const RECV: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes: "RECV from different endpoints commutes. Same endpoint serializes.",
    };

    pub const REPLY_RECV: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes: "REPLY_RECV on different endpoints commutes. Same endpoint serializes.",
    };

    pub const INVOKE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::DependsOnMethod,
        resource_extractor: ResourceExtractor::MethodDependent,
        notes: "Commutativity depends on the invoke method. See invoke_commutativity module.",
    };

    pub const CAP_MINT: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes:
            "Minting caps in different slots/processes commutes. Same destination slot serializes.",
    };

    pub const CAP_REVOKE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Conflicts,
        resource_extractor: ResourceExtractor::Global,
        notes: "Revocation walks the global derivation tree. Must be serialized.",
    };

    pub const EXIT: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::None,
        notes: "Thread exit only affects the exiting thread and its owned objects.",
    };
}

/// Standard commutativity specs for invoke methods
pub mod invoke_commutativity {
    use super::{Commutativity, CommutativitySpec, ResourceExtractor};

    // Factory methods
    pub const FACTORY_NEW_ENDPOINT: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::None,
        notes: "Creates independent endpoint objects",
    };

    pub const FACTORY_NEW_NOTIFICATION: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::None,
        notes: "Creates independent notification objects",
    };

    pub const FACTORY_NEW_ADDRESS_SPACE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::None,
        notes: "Creates independent address space objects",
    };

    pub const FACTORY_NEW_THREAD: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot, // destination cap slot for thread cap
        notes: "Creates independent thread/process. The AddressSpace cap (caps[0]) is read-only for this operation.",
    };

    // Thread methods
    pub const THREAD_EXIT: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    pub const THREAD_KILL: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    pub const THREAD_SUSPEND: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    pub const THREAD_RESUME: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    pub const THREAD_SET_PRIORITY: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    pub const THREAD_SET_TLS: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    pub const THREAD_BIND_DEATH_NOTIFICATION: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread's notification binding",
    };

    pub const THREAD_CREATE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot, // destination cap slot
        notes: "Creates a new thread in the same process. Only the target process's thread table is modified.",
    };

    pub const THREAD_SET_ENTRY: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread (must be SUSPENDED)",
    };

    pub const THREAD_SET_FOREIGN: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    pub const THREAD_TRAP_READ: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Read-only operation on the target thread",
    };

    pub const THREAD_DEFER: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the calling thread's reply slot",
    };

    pub const THREAD_REGS_READ: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Read-only operation on the target thread",
    };

    pub const THREAD_REGS_WRITE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread (must be SUSPENDED)",
    };

    // AddressSpace methods
    pub const AS_MAP: CommutativitySpec = CommutativitySpec {
        class: Commutativity::CommutesDisjointRanges,
        resource_extractor: ResourceExtractor::VaddrRange {
            vaddr_arg: 0,
            pages_arg: 1,
        },
        notes:
            "MAP on disjoint virtual address ranges commutes. Overlapping ranges conflict (EEXIST).",
    };

    pub const AS_UNMAP: CommutativitySpec = CommutativitySpec {
        class: Commutativity::CommutesDisjointRanges,
        resource_extractor: ResourceExtractor::VaddrRange {
            vaddr_arg: 0,
            pages_arg: 1,
        },
        notes: "UNMAP on disjoint ranges commutes. Overlapping ranges conflict.",
    };

    pub const AS_PROTECT: CommutativitySpec = CommutativitySpec {
        class: Commutativity::CommutesDisjointRanges,
        resource_extractor: ResourceExtractor::VaddrRange {
            vaddr_arg: 0,
            pages_arg: 1,
        }, // pages=1 implied
        notes: "PROTECT on disjoint pages commutes. Same page conflicts.",
    };

    pub const AS_SET_FAULT_POOL: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Conflicts,
        resource_extractor: ResourceExtractor::ObjId, // the AS object
        notes: "Modifies the AS's fault pool pointer. Serialized per AS.",
    };

    pub const AS_FORK: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Conflicts,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "FORK clones the entire AS page table. Must be serialized per source AS.",
    };

    pub const AS_DESTROY: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Conflicts,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Destroys the AS. Must be serialized.",
    };

    // Reply methods
    pub const REPLY_SEND: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId, // the Reply cap's ObjId = caller TID
        notes: "Each Reply cap is one-shot and tied to a specific caller thread.",
    };
}
