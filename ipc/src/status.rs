//! Status / error space (schema §7): `i32`, shared by syscall returns and
//! server reply `w0`. The authoritative table lives in
//! `sdk/docs/ipc-schema.md`; this module mirrors it exactly. `servers/` must
//! not invent codes outside it.
#![forbid(unsafe_code)]

pub const OK: i32 = 0;
pub const EBADCAP: i32 = -1;
pub const ERIGHTS: i32 = -2;
pub const EBADARG: i32 = -3;
pub const EWOULDBLOCK: i32 = -4;
pub const ECANCELED: i32 = -5;
pub const EREVOKED: i32 = -6;
pub const EFAULT: i32 = -7;
pub const ENOMEM: i32 = -8;
pub const ETIMEDOUT: i32 = -9;
pub const EBUSY: i32 = -10;
pub const EDEAD: i32 = -11;
pub const EBADSTATE: i32 = -12;
pub const ETOOBIG: i32 = -13;
pub const ENOSYS: i32 = -14;
pub const ENOENT: i32 = -15;
pub const EEXIST: i32 = -16;
pub const EISDIR: i32 = -17;
pub const ENOTDIR: i32 = -18;
pub const ENOTEMPTY: i32 = -19;
pub const EMFILE: i32 = -20;
pub const EACCES: i32 = -21;

/// Human-readable name for diagnostics (kernel logging / tests).
pub const fn name(code: i32) -> &'static str {
    match code {
        OK => "OK",
        EBADCAP => "EBADCAP",
        ERIGHTS => "ERIGHTS",
        EBADARG => "EBADARG",
        EWOULDBLOCK => "EWOULDBLOCK",
        ECANCELED => "ECANCELED",
        EREVOKED => "EREVOKED",
        EFAULT => "EFAULT",
        ENOMEM => "ENOMEM",
        ETIMEDOUT => "ETIMEDOUT",
        EBUSY => "EBUSY",
        EDEAD => "EDEAD",
        EBADSTATE => "EBADSTATE",
        ETOOBIG => "ETOOBIG",
        ENOSYS => "ENOSYS",
        ENOENT => "ENOENT",
        EEXIST => "EEXIST",
        EISDIR => "EISDIR",
        ENOTDIR => "ENOTDIR",
        ENOTEMPTY => "ENOTEMPTY",
        EMFILE => "EMFILE",
        EACCES => "EACCES",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_cover_full_table() {
        for code in [
            OK,
            EBADCAP,
            ERIGHTS,
            EBADARG,
            EWOULDBLOCK,
            ECANCELED,
            EREVOKED,
            EFAULT,
            ENOMEM,
            ETIMEDOUT,
            EBUSY,
            EDEAD,
            EBADSTATE,
            ETOOBIG,
            ENOSYS,
        ] {
            assert_ne!(name(code), "UNKNOWN", "{code} missing a name");
        }
        assert_eq!(name(999), "UNKNOWN");
    }
}
