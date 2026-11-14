//! netwatch's internals, exposed so that its binary, examples and tests can reach
//! them. **This is not a public API.** It can change in any release, whatever the
//! version number suggests, and [STABILITY.md] doesn't cover it.
//!
//! [STABILITY.md]: https://github.com/matthart1983/netwatch/blob/main/STABILITY.md

// Clippy lints deliberately allowed crate-wide. Each is a decision, not an
// oversight — the alternative clippy suggests is worse for this codebase, and
// leaving them as warnings meant the real signal was buried in noise nobody
// read. With these declared, `-D warnings` becomes a gate CI can actually
// enforce.
//
// `collapsible_match` — collapsing `Arm => { if cond { .. } }` into
// `Arm if cond => { .. }` moves the condition into a match guard, and both
// places it fires are places that must not happen:
//
//   * `event.rs` would put a channel `send()` — a side effect — inside a
//     pattern guard.
//   * `app.rs` is a several-thousand-line ordered keyboard match. A guarded
//     arm falls through when the guard fails, so collapsing changes which
//     later arm receives the key. That exact failure has already bitten this
//     file once; see the ordering comment above the Egress `x` handler.
//
// Clippy's own autofix demonstrated the risk: applied blindly it produced a
// non-exhaustive match in `dns_cache.rs` and failed to compile.
//
// `too_many_arguments` — nine rendering and collection functions take 8–14
// parameters. Bundling them into structs would add a type per call site and
// change nothing about behaviour or clarity; a draw function that needs eight
// pieces of state is not improved by hiding that fact.
//
// `vec_init_then_push` — the two help-screen builders push ~100 lines each,
// interleaved with conditionals and section comments. Folding the leading run
// into `vec![]` would leave one function built two different ways.
#![allow(clippy::collapsible_match)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::vec_init_then_push)]

pub mod app;
pub mod atomic_file;
pub mod cli;
pub mod clipboard;
pub mod collectors;
pub mod config;
pub mod diagnose;
pub mod dpi;
pub mod ebpf;
pub mod event;
pub mod geoip_update;
pub mod graph;
pub mod http;
pub mod logging;
pub mod metrics;
pub mod owner_only;
pub mod platform;
pub mod remote;
pub mod runtime;
pub mod sandbox;
pub mod schemas;
pub mod sort;
pub mod state;
pub mod theme;
pub mod ui;
pub mod uptime;

#[cfg(test)]
mod scale_tests;
#[cfg(test)]
mod testutil;

/// A simple hello world function that returns a greeting message.
pub fn hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world() {
        assert_eq!(hello_world(), "Hello, World!");
    }
}

/// Binds `WaitOnAddress` and `WakeByAddressAll` to the DLL they live in,
/// before the linker can take them from somewhere else.
///
/// `pcap` depends on `windows-sys` 0.36, which links `windows.lib`: one
/// import library for the whole Win32 API. It maps these two functions to
/// `vertdll.dll`, the runtime for code inside a VBS enclave, which exports
/// functions of the same names. From Rust 1.100 the standard library's own
/// references to them are resolved by the first library link.exe finds them
/// in, searching onward from the standard library, and in the unit-test
/// binary that is `windows.lib`. The process then loaded `vertdll.dll` and
/// died with an access violation the first time a thread parked: every unit
/// test, on its first channel receive.
///
/// A reference from one of this crate's own objects is resolved first, and
/// against the library named here. Once the symbols are defined, the
/// standard library's references need no search. The release binary was
/// never affected; this keeps `cargo test` working on Windows.
#[cfg(all(windows, target_env = "msvc"))]
mod wait_on_address {
    use core::ffi::c_void;

    #[link(name = "synchronization")]
    unsafe extern "system" {
        fn WaitOnAddress(
            address: *const c_void,
            compare_address: *const c_void,
            address_size: usize,
            milliseconds: u32,
        ) -> i32;
        fn WakeByAddressAll(address: *const c_void);
    }

    #[used]
    static WAIT: unsafe extern "system" fn(*const c_void, *const c_void, usize, u32) -> i32 =
        WaitOnAddress;
    #[used]
    static WAKE: unsafe extern "system" fn(*const c_void) = WakeByAddressAll;
}
