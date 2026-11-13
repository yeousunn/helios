//! Non-aarch64 stub so `hal-aarch64` compiles on other hosts.
//! The real aarch64 implementations live in the `#[cfg(target_arch = "aarch64")]`
//! modules; this stub exists only so the crate is usable cross-platform.

pub struct ContextBackendAarch64;
pub struct PagingBackendAarch64;
pub struct BackendFactoryAarch64;
pub struct AArch64TrapFrame;
pub struct TrapDecodeAarch64;

impl Default for ContextBackendAarch64 {
    fn default() -> Self {
        Self
    }
}
impl Default for PagingBackendAarch64 {
    fn default() -> Self {
        Self
    }
}
impl Default for BackendFactoryAarch64 {
    fn default() -> Self {
        Self
    }
}
