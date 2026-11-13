//! Non-riscv64 stub so `hal-riscv64` compiles on other hosts.
//! The real riscv64 implementations live in the `#[cfg(target_arch = "riscv64")]`
//! modules; this stub exists only so the crate is usable cross-platform.

pub struct ContextBackendRiscv64;
pub struct PagingBackendRiscv64;
pub struct BackendFactoryRiscv64;
pub struct Riscv64TrapFrame;
pub struct TrapDecodeRiscv64;

impl Default for ContextBackendRiscv64 {
    fn default() -> Self {
        Self
    }
}

impl Default for PagingBackendRiscv64 {
    fn default() -> Self {
        Self
    }
}

impl Default for BackendFactoryRiscv64 {
    fn default() -> Self {
        Self
    }
}
