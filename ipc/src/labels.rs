//! Label registry (schema §6). GLM maintains this table; ranges are owned
//! per server. Receivers dispatch on `(version, label)`.
#![forbid(unsafe_code)]

pub mod kernel {
    pub const FAULT_PAGE: u16 = 0x0001;
    pub const FAULT_RESOLVE: u16 = 0x0002;
    pub const NOTIFY: u16 = 0x0003;
    pub const IRQ: u16 = 0x0004;
}

pub mod process {
    pub const BASE: u16 = 0x0100;
}

pub mod vfs {
    pub const BASE: u16 = 0x0200;
}

pub mod auth {
    pub const BASE: u16 = 0x0300;
}

pub mod net {
    pub const BASE: u16 = 0x0400;
}

pub mod device {
    pub const BASE: u16 = 0x0500;
}

pub mod graphics {
    pub const BASE: u16 = 0x0600;
}

pub mod experimental {
    pub const BASE: u16 = 0x8000;
}
