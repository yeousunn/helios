//! POSIX surface, v0 subset: open-flag constants and the errno convention.
//!
//! The kernel, PS, and the VFS report protocol `ipc::status` codes; POSIX
//! callers see them through the aliases below (the translation boundary per
//! the design's "servers never invent errno" rule — v0 keeps the protocol
//! codes, later slices remap to real Linux errno numbers).

/// Open for reading (maps to the VFS `OPEN` op).
pub const O_RDONLY: u32 = 0;
/// Create the file (maps to the VFS `CREATE` op, which opens READ|WRITE).
pub const O_CREAT: u32 = 1 << 0;
/// Truncate on open (reserved; v0 VFS has no truncate-on-open).
pub const O_TRUNC: u32 = 1 << 1;
/// Write flag for the client's internal open-mode selection.
pub const O_WRONLY: u32 = 1 << 2;

// Errno aliases (protocol codes; see `ipc::status`).
pub use ipc::status::{EBADARG as EINVAL, EBADCAP as EBADF, ENOENT, ENOMEM, ENOSYS};

// The v0 protocol has no EIO; reserve the name for the POSIX surface.
pub const EIO: i32 = -1000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_bits_are_distinct() {
        assert_eq!(O_RDONLY, 0);
        assert_ne!(O_CREAT, O_TRUNC);
        assert_ne!(O_TRUNC, O_WRONLY);
        assert_eq!(O_WRONLY & O_TRUNC, 0);
    }

    #[test]
    fn errno_aliases_match_protocol_codes() {
        assert_eq!(EINVAL, ipc::status::EBADARG);
        assert_eq!(EBADF, ipc::status::EBADCAP);
        assert_eq!(ENOENT, ipc::status::ENOENT);
    }
}
