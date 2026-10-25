//! Finding Npcap's `wpcap.dll` at startup on Windows.
//!
//! Npcap 1.x installs its DLLs into `%SystemRoot%\System32\Npcap\` rather than
//! `System32` itself, so it can sit beside a WinPcap install instead of
//! replacing it. That subdirectory is **not** on the loader's default search
//! path, so a binary importing `wpcap.dll` by name doesn't find it: the process
//! dies before `main()` runs and Windows shows a bare "wpcap.dll was not found"
//! message box (issue #47). The installer's *Install Npcap in WinPcap
//! API-compatible Mode* option also copies the DLLs into `System32`, which is
//! why the same machine works after reinstalling with that box ticked — but it
//! is unchecked by default, so the default install is the one that fails.
//!
//! The fix is the one Wireshark and nmap use for the same layout: tell the
//! loader where Npcap lives, then load `wpcap.dll` ourselves before any capture
//! code needs it. `build.rs` marks the wpcap imports delay-loaded so nothing
//! resolves them at process start, which leaves a window in `main()` to do this
//! — and to fail with a sentence a user can act on instead of a modal.
//!
//! Setting the directory also covers `Packet.dll`, which `wpcap.dll` imports
//! and which lives beside it: the loader searches the `SetDllDirectoryW`
//! directory when resolving a dependency, and would otherwise miss it too.

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryW, SetDllDirectoryW};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_STATUS,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// `%SystemRoot%\System32`, asked for rather than assumed — Windows is not
/// always on `C:`, and `System32` is not always named that on non-English
/// installs of some very old versions.
///
/// Asking also gets the bitness right for free: Npcap ships 64-bit DLLs under
/// `System32\Npcap` and 32-bit ones under `SysWOW64\Npcap`, and WOW64 redirects
/// this call to `SysWOW64` for a 32-bit process. Each build therefore finds the
/// DLLs it can actually load. A hardcoded path would be wrong for one of them.
fn system_directory() -> Option<PathBuf> {
    // MAX_PATH is the documented ceiling for this call.
    let mut buf = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 || len >= buf.len() {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(&buf[..len])))
}

/// Static file-presence check. Does not load the DLL or contact a driver.
pub fn installed() -> bool {
    system_directory()
        .is_some_and(|p| p.join("Npcap/wpcap.dll").is_file() || p.join("wpcap.dll").is_file())
}

/// The `npcap` driver service's `dwCurrentState`, or the Win32 error that kept
/// us from reading it (1060 when no such service is registered).
///
/// This asks the Service Control Manager, which normally needs no elevation
/// for a status query, so doctor can tell "Npcap's files are there but its
/// driver is not running" from a working install without loading `wpcap.dll`
/// or opening the driver. Static doctor promises to do neither. Wireshark asks
/// the same way before warning "The NPF driver isn't running".
pub fn driver_service_state() -> Result<u32, u32> {
    service_state("npcap")
}

fn service_state(name: &str) -> Result<u32, u32> {
    // GetLastError, called straight after the call that failed:
    // CloseServiceHandle can overwrite it.
    let last_error = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
    // SAFETY: null machine and database names mean the local, active service
    // database; the handle is checked for null before use.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(last_error());
    }
    let name = wide(std::ffi::OsStr::new(name));
    // SAFETY: `manager` is the live handle opened above, and `name` is a
    // NUL-terminated UTF-16 string that outlives the call.
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
    let state = if service.is_null() {
        Err(last_error())
    } else {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: `service` was opened with SERVICE_QUERY_STATUS, and `status`
        // is a writable SERVICE_STATUS the call fills in.
        let ok = unsafe { QueryServiceStatus(service, &mut status) } != 0;
        let state = if ok {
            Ok(status.dwCurrentState)
        } else {
            Err(last_error())
        };
        // SAFETY: `service` is a handle this function opened and closes once.
        unsafe { CloseServiceHandle(service) };
        state
    };
    // SAFETY: as above, for the manager handle.
    unsafe { CloseServiceHandle(manager) };
    state
}

/// Add Npcap's install directory to the DLL search path, returning it when it
/// was found and accepted.
///
/// Absent (a WinPcap-compatible install, or no Npcap at all) we leave the
/// search path alone: the default order already covers `System32`, which is
/// where a compatible-mode install puts the DLLs.
fn add_npcap_dir_to_search_path() -> Option<PathBuf> {
    let dir = system_directory()?.join("Npcap");
    if !dir.is_dir() {
        return None;
    }
    let ok = unsafe { SetDllDirectoryW(wide(dir.as_os_str()).as_ptr()) } != 0;
    ok.then_some(dir)
}

/// Load `wpcap.dll` before anything else asks for it.
///
/// On success the module stays loaded for the life of the process, so the
/// delay-loaded imports in the capture path resolve against it without
/// searching again — and, more to the point, without being able to fail
/// somewhere we can't report it.
///
/// The error is a whole message ready to print, not a cause to wrap: it is the
/// last thing a user sees before we exit, and it has one job — name the missing
/// dependency and where to get it.
pub fn ensure_wpcap() -> Result<(), String> {
    let npcap_dir = add_npcap_dir_to_search_path();

    let handle = unsafe { LoadLibraryW(wide(std::ffi::OsStr::new("wpcap.dll")).as_ptr()) };
    if !handle.is_null() {
        return Ok(());
    }

    let searched = match npcap_dir {
        Some(dir) => format!("{} and the standard DLL search path", dir.display()),
        None => "the standard DLL search path".to_string(),
    };
    Err(format!(
        "netwatch: could not load wpcap.dll.\n\n\
         NetWatch captures packets through Npcap on Windows. Install it from\n\
         https://npcap.com/#download and run netwatch again.\n\n\
         (Looked in {searched}.)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The system directory is the anchor for everything else here; if this
    /// call ever starts failing, the search-path fix silently stops applying
    /// and we are back to the default loader order.
    #[test]
    fn system_directory_is_found_and_absolute() {
        let dir = system_directory().expect("GetSystemDirectoryW returned nothing");
        assert!(dir.is_absolute(), "not absolute: {}", dir.display());
        assert!(dir.is_dir(), "not a directory: {}", dir.display());
    }

    /// On a CI runner Npcap itself isn't installed — only the SDK, which is
    /// headers and an import library, not `System32\Npcap`. Either answer is
    /// correct; what must not happen is a panic or a bogus path.
    #[test]
    fn npcap_dir_probe_is_honest() {
        if let Some(dir) = add_npcap_dir_to_search_path() {
            assert!(dir.is_dir(), "returned a path that isn't there");
        }
    }

    /// The service query decodes a real answer, checked against services
    /// whose state is known on every Windows rather than against Npcap, which
    /// the CI runner does not have. RpcSs cannot be stopped, so it is always
    /// SERVICE_RUNNING (4); 1060 is ERROR_SERVICE_DOES_NOT_EXIST.
    #[test]
    fn service_query_reads_known_services() {
        assert_eq!(service_state("RpcSs"), Ok(4));
        assert_eq!(service_state("netwatch-no-such-service"), Err(1060));
    }
}
