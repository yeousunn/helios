//! Capability types and rights definitions

use core::fmt;

/// Kernel object types (must match kernel's caps::ObjType)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u64)]
pub enum ObjType {
    /// Invalid/uninitialized
    None = 0,
    /// Endpoint for synchronous IPC
    Endpoint = 1,
    /// Notification for async signalling
    Notification = 2,
    /// Address space (page table root)
    AddressSpace = 3,
    /// Thread control block
    Thread = 4,
    /// Physical frame
    Frame = 5,
    /// IRQ handler
    Irq = 6,
    /// Capability table (CNode)
    CNode = 7,
    /// Untyped memory
    Untyped = 8,
    /// Region (carved from Untyped)
    Region = 9,
    /// Scheduling context
    SchedContext = 10,
    /// Security domain
    Domain = 11,
    /// I/O space (IOMMU domain)
    IOSpace = 12,
    /// Core grant
    CoreGrant = 13,
    /// Reply capability (one-shot)
    Reply = 14,
    /// Factory (root object creator)
    Factory = 15,
    /// Port (keyed wait queue)
    Port = 16,
    /// Ring (submission/completion queues)
    Ring = 17,
    /// Special: any object type (for descriptors that accept multiple)
    Any = 0xFF,
}

impl ObjType {
    /// All valid object types (excluding None and Any)
    pub const ALL: &[ObjType] = &[
        ObjType::Endpoint,
        ObjType::Notification,
        ObjType::AddressSpace,
        ObjType::Thread,
        ObjType::Frame,
        ObjType::Irq,
        ObjType::CNode,
        ObjType::Untyped,
        ObjType::Region,
        ObjType::SchedContext,
        ObjType::Domain,
        ObjType::IOSpace,
        ObjType::CoreGrant,
        ObjType::Reply,
        ObjType::Factory,
        ObjType::Port,
        ObjType::Ring,
    ];

    /// Check if this is a valid concrete object type
    pub fn is_concrete(self) -> bool {
        matches!(
            self,
            ObjType::Endpoint
                | ObjType::Notification
                | ObjType::AddressSpace
                | ObjType::Thread
                | ObjType::Frame
                | ObjType::Irq
                | ObjType::CNode
                | ObjType::Untyped
                | ObjType::Region
                | ObjType::SchedContext
                | ObjType::Domain
                | ObjType::IOSpace
                | ObjType::CoreGrant
                | ObjType::Reply
                | ObjType::Factory
                | ObjType::Port
                | ObjType::Ring
        )
    }
}

impl fmt::Display for ObjType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Capability rights bitmask (must match ipc::Rights)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rights(pub u16);

impl Rights {
    // SeL4-style rights (syscall-abi §5)
    pub const READ: Rights = Rights(1 << 0); // bit 0: read memory / receive
    pub const WRITE: Rights = Rights(1 << 1); // bit 1: write memory
    pub const EXEC: Rights = Rights(1 << 2); // bit 2: execute memory
    pub const GRANT: Rights = Rights(1 << 3); // bit 3: can delegate/mint
    pub const SEND: Rights = Rights(1 << 4); // bit 4: can send to endpoint
    pub const RECV: Rights = Rights(1 << 5); // bit 5: can receive from endpoint
    pub const SIGNAL: Rights = Rights(1 << 6); // bit 6: can signal notification
    pub const MAP: Rights = Rights(1 << 7); // bit 7: can map in address space
    pub const CONTROL: Rights = Rights(1 << 8); // bit 8: thread control (kill, suspend, etc.)
    pub const REVOKE: Rights = Rights(1 << 9); // bit 9: can revoke
    pub const ACK: Rights = Rights(1 << 10); // bit 10: can acknowledge IRQ

    /// All defined rights bits
    pub const ALL: Rights = Rights(
        Self::READ.0
            | Self::WRITE.0
            | Self::EXEC.0
            | Self::GRANT.0
            | Self::SEND.0
            | Self::RECV.0
            | Self::SIGNAL.0
            | Self::MAP.0
            | Self::CONTROL.0
            | Self::REVOKE.0
            | Self::ACK.0,
    );

    /// Rights for a basic endpoint cap (SEND | RECV | GRANT)
    pub const ENDPOINT_DEFAULT: Rights = Rights(Self::SEND.0 | Self::RECV.0 | Self::GRANT.0);

    /// Rights for a notification cap (SIGNAL | RECV | GRANT)
    pub const NOTIFICATION_DEFAULT: Rights = Rights(Self::SIGNAL.0 | Self::RECV.0 | Self::GRANT.0);

    /// Rights for an address space cap (MAP | GRANT)
    pub const ADDRESS_SPACE_DEFAULT: Rights = Rights(Self::MAP.0 | Self::GRANT.0);

    /// Rights for a thread cap (CONTROL | GRANT)
    pub const THREAD_DEFAULT: Rights = Rights(Self::CONTROL.0 | Self::GRANT.0);

    /// Rights for a frame cap (READ | WRITE | EXEC | GRANT)
    pub const FRAME_DEFAULT: Rights =
        Rights(Self::READ.0 | Self::WRITE.0 | Self::EXEC.0 | Self::GRANT.0);

    /// Rights for a reply cap (SEND)
    pub const REPLY_DEFAULT: Rights = Rights(Self::SEND.0);

    /// Check if `self` contains all rights in `other`
    pub const fn contains(self, other: Rights) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Union of two rights sets
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// Intersection of two rights sets
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    /// Difference (self - other)
    pub const fn difference(self, other: Rights) -> Rights {
        Rights(self.0 & !other.0)
    }

    /// Check if any rights are set
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Get the raw bits
    pub const fn bits(self) -> u16 {
        self.0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, other: Rights) -> Rights {
        self.union(other)
    }
}

impl core::ops::BitAnd for Rights {
    type Output = Rights;
    fn bitand(self, other: Rights) -> Rights {
        self.intersect(other)
    }
}

impl core::ops::BitOrAssign for Rights {
    fn bitor_assign(&mut self, other: Rights) {
        self.0 |= other.0;
    }
}

impl core::ops::BitAndAssign for Rights {
    fn bitand_assign(&mut self, other: Rights) {
        self.0 &= other.0;
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let names = [
            (Self::READ, "READ"),
            (Self::WRITE, "WRITE"),
            (Self::EXEC, "EXEC"),
            (Self::GRANT, "GRANT"),
            (Self::SEND, "SEND"),
            (Self::RECV, "RECV"),
            (Self::SIGNAL, "SIGNAL"),
            (Self::MAP, "MAP"),
            (Self::CONTROL, "CONTROL"),
            (Self::REVOKE, "REVOKE"),
            (Self::ACK, "ACK"),
        ];
        for (right, name) in names {
            if self.contains(right) {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{}", name)?;
                first = false;
            }
        }
        if first {
            write!(f, "NONE")?;
        }
        Ok(())
    }
}
