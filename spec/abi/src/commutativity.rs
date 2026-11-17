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
    VaddrRange {
        /// Base virtual address
        base: u64,
        /// Number of pages
        pages: u64,
    },
    /// Capability slot: (process_id, slot)
    CapSlot {
        /// Process ID
        pid: u64,
        /// Capability slot index
        slot: u32,
    },
    /// Object ID: (object_type, object_id)
    ObjId {
        /// Object type
        obj_type: u8,
        /// Object ID
        obj_id: u64,
    },
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
    VaddrRange {
        /// Argument index for virtual address
        vaddr_arg: usize,
        /// Argument index for page count
        pages_arg: usize,
    },
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

    /// YIELD syscall commutativity
    pub const YIELD: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::None,
        notes: "YIELD only affects the calling thread's scheduling state",
    };

    /// SEND syscall commutativity
    pub const SEND: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes: "SEND to different endpoints commutes. SEND to same endpoint serializes on the endpoint's mailbox lock.",
    };

    /// CALL syscall commutativity
    pub const CALL: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes: "CALL to different endpoints commutes. Same endpoint serializes.",
    };

    /// RECV syscall commutativity
    pub const RECV: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes: "RECV from different endpoints commutes. Same endpoint serializes.",
    };

    /// REPLY_RECV syscall commutativity
    pub const REPLY_RECV: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes: "REPLY_RECV on different endpoints commutes. Same endpoint serializes.",
    };

    /// INVOKE syscall commutativity
    pub const INVOKE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::DependsOnMethod,
        resource_extractor: ResourceExtractor::MethodDependent,
        notes: "Commutativity depends on the invoke method. See invoke_commutativity module.",
    };

    /// CAP_MINT syscall commutativity
    pub const CAP_MINT: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot,
        notes:
            "Minting caps in different slots/processes commutes. Same destination slot serializes.",
    };

    /// CAP_REVOKE syscall commutativity
    pub const CAP_REVOKE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Conflicts,
        resource_extractor: ResourceExtractor::Global,
        notes: "Revocation walks the global derivation tree. Must be serialized.",
    };

    /// EXIT syscall commutativity
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
    /// FACTORY_NEW_ENDPOINT invoke commutativity
    pub const FACTORY_NEW_ENDPOINT: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::None,
        notes: "Creates independent endpoint objects",
    };

    /// FACTORY_NEW_NOTIFICATION invoke commutativity
    pub const FACTORY_NEW_NOTIFICATION: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::None,
        notes: "Creates independent notification objects",
    };

    /// FACTORY_NEW_ADDRESS_SPACE invoke commutativity
    pub const FACTORY_NEW_ADDRESS_SPACE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::None,
        notes: "Creates independent address space objects",
    };

    /// FACTORY_NEW_THREAD invoke commutativity
    pub const FACTORY_NEW_THREAD: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot, // destination cap slot for thread cap
        notes: "Creates independent thread/process. The AddressSpace cap (caps[0]) is read-only for this operation. w1 is descriptor-overlay territory at cap_count 3 and is ignored by the kernel (ADR-086 proposal; RFC-0004's stack top ships on THREAD_CREATE w1 only).",
    };

    /// FACTORY_RETYPE invoke commutativity (ADR-088/RFC-0005 §3)
    pub const FACTORY_RETYPE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::CommutesDisjointRanges,
        resource_extractor: ResourceExtractor::ObjId, // the source Untyped's ObjId (caps[0])
        notes: "Retypes on different Untypeds commute ([R-COMMUTER]); on the same Untyped they conflict — carving is ordered, the source shrinks in place.",
    };

    // Thread methods
    /// THREAD_EXIT invoke commutativity
    pub const THREAD_EXIT: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    /// THREAD_KILL invoke commutativity
    pub const THREAD_KILL: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    /// THREAD_SUSPEND invoke commutativity
    pub const THREAD_SUSPEND: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    /// THREAD_RESUME invoke commutativity
    pub const THREAD_RESUME: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    /// THREAD_SET_PRIORITY invoke commutativity
    pub const THREAD_SET_PRIORITY: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    /// THREAD_SET_TLS invoke commutativity
    pub const THREAD_SET_TLS: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    /// THREAD_BIND_NOTIFICATION invoke commutativity (syscall-abi §3.1)
    pub const THREAD_BIND_NOTIFICATION: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread's wake-notification binding",
    };

    /// THREAD_BIND_DEATH_NOTIFICATION invoke commutativity
    pub const THREAD_BIND_DEATH_NOTIFICATION: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread's death-notification binding",
    };

    /// THREAD_BIND_FAULT_EP invoke commutativity (ADR-088: Thread label 18)
    pub const THREAD_BIND_FAULT_EP: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Conflicts,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Rebinds the target thread's fault-routing state (RFC-0005 §ABI row 2); serialized against everything that touches that thread.",
    };

    /// THREAD_CREATE invoke commutativity
    pub const THREAD_CREATE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::CapSlot, // destination cap slot
        notes: "Creates a new thread in the same process. Only the target process's thread table is modified. w1 (initial stack top, RFC-0004/ADR-085) is a value copied into the child frame; callers choose disjoint tops — two threads with the same top alias one stack (caller bug).",
    };

    /// THREAD_SET_ENTRY invoke commutativity
    pub const THREAD_SET_ENTRY: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread (must be SUSPENDED)",
    };

    /// THREAD_SET_FOREIGN invoke commutativity
    pub const THREAD_SET_FOREIGN: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread",
    };

    /// THREAD_TRAP_READ invoke commutativity
    pub const THREAD_TRAP_READ: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Read-only operation on the target thread",
    };

    /// THREAD_DEFER invoke commutativity
    pub const THREAD_DEFER: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the calling thread's reply slot",
    };

    /// THREAD_REGS_READ invoke commutativity
    pub const THREAD_REGS_READ: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Read-only operation on the target thread",
    };

    /// THREAD_REGS_WRITE invoke commutativity
    pub const THREAD_REGS_WRITE: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Only affects the target thread (must be SUSPENDED)",
    };

    // AddressSpace methods
    /// AS_MAP invoke commutativity
    pub const AS_MAP: CommutativitySpec = CommutativitySpec {
        class: Commutativity::CommutesDisjointRanges,
        resource_extractor: ResourceExtractor::VaddrRange {
            vaddr_arg: 0,
            pages_arg: 1,
        },
        notes:
            "MAP on disjoint virtual address ranges commutes. Overlapping ranges conflict (EEXIST).",
    };

    /// AS_UNMAP invoke commutativity
    pub const AS_UNMAP: CommutativitySpec = CommutativitySpec {
        class: Commutativity::CommutesDisjointRanges,
        resource_extractor: ResourceExtractor::VaddrRange {
            vaddr_arg: 0,
            pages_arg: 1,
        },
        notes: "UNMAP on disjoint ranges commutes. Overlapping ranges conflict.",
    };

    /// AS_PROTECT invoke commutativity
    pub const AS_PROTECT: CommutativitySpec = CommutativitySpec {
        class: Commutativity::CommutesDisjointRanges,
        resource_extractor: ResourceExtractor::VaddrRange {
            vaddr_arg: 0,
            pages_arg: 1,
        }, // pages=1 implied
        notes: "PROTECT on disjoint pages commutes. Same page conflicts.",
    };

    /// AS_SET_FAULT_POOL invoke commutativity
    pub const AS_SET_FAULT_POOL: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Conflicts,
        resource_extractor: ResourceExtractor::ObjId, // the AS object
        notes: "Modifies the AS's fault pool pointer. Serialized per AS.",
    };

    /// AS_FORK invoke commutativity
    pub const AS_FORK: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Conflicts,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "FORK clones the entire AS page table. Must be serialized per source AS.",
    };

    /// AS_DESTROY invoke commutativity
    pub const AS_DESTROY: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Conflicts,
        resource_extractor: ResourceExtractor::ObjId,
        notes: "Destroys the AS. Must be serialized.",
    };

    // Reply methods
    /// REPLY_SEND invoke commutativity
    pub const REPLY_SEND: CommutativitySpec = CommutativitySpec {
        class: Commutativity::Commutes,
        resource_extractor: ResourceExtractor::ObjId, // the Reply cap's ObjId = caller TID
        notes: "Each Reply cap is one-shot and tied to a specific caller thread.",
    };
}
