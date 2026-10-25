//! The kernel's TCP and UDP tables through IP Helper, with the PID that owns
//! each socket, and the names of those processes from a Toolhelp32 snapshot.
//!
//! These replace `netstat -ano` and `tasklist`: two processes spawned on every
//! connections tick, whose output was in the display language. The calls here
//! return numbers and UTF-16, the same on every install. Decoding the rows is
//! in `platform::socket_table`, where it is tested on every host.

use crate::platform::socket_table::{self, Socket, Tcp4Row, Tcp6Row, Udp4Row, Udp6Row};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::mem::offset_of;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ENOUGH_MEMORY, ERROR_NO_DATA,
    INVALID_HANDLE_VALUE, NO_ERROR, TRUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

/// Every TCP socket (listeners included) and every UDP socket on the host,
/// IPv4 before IPv6, each table sorted by local endpoint as netstat listed
/// them. A family the host has no table for (ERROR_NO_DATA) is empty, not a
/// failure. `Err` carries the Win32 error from the first table that could not
/// be read. The caller then falls back to netstat for all four rather than
/// show a list with one family silently missing.
pub fn sockets() -> Result<Vec<Socket>, u32> {
    let tcp4 = read_table::<MIB_TCPTABLE_OWNER_PID>(|buf, size| {
        // SAFETY: `read_table` passes a writable buffer of `*size` bytes,
        // aligned for the table, and a live pointer to its size.
        unsafe {
            GetExtendedTcpTable(
                buf,
                size,
                TRUE,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }
    })?;
    let tcp6 = read_table::<MIB_TCP6TABLE_OWNER_PID>(|buf, size| {
        // SAFETY: as for the IPv4 table above.
        unsafe {
            GetExtendedTcpTable(
                buf,
                size,
                TRUE,
                u32::from(AF_INET6),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }
    })?;
    let udp4 = read_table::<MIB_UDPTABLE_OWNER_PID>(|buf, size| {
        // SAFETY: as for the TCP tables above.
        unsafe { GetExtendedUdpTable(buf, size, TRUE, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0) }
    })?;
    let udp6 = read_table::<MIB_UDP6TABLE_OWNER_PID>(|buf, size| {
        // SAFETY: as for the TCP tables above.
        unsafe { GetExtendedUdpTable(buf, size, TRUE, u32::from(AF_INET6), UDP_TABLE_OWNER_PID, 0) }
    })?;

    let mut out = Vec::with_capacity(tcp4.len() + tcp6.len() + udp4.len() + udp6.len());
    out.extend(tcp4.iter().map(|r| Socket::from(&Tcp4Row::from(r))));
    out.extend(tcp6.iter().map(|r| Socket::from(&Tcp6Row::from(r))));
    out.extend(udp4.iter().map(|r| Socket::from(&Udp4Row::from(r))));
    out.extend(udp6.iter().map(|r| Socket::from(&Udp6Row::from(r))));
    Ok(out)
}

/// The image name (`chrome.exe`) of each of `pids` still running, from one
/// Toolhelp32 snapshot per call. tasklist walks the same process list, so the
/// names are the ones it printed, and anything keyed on them (egress
/// policies, process history) carries over. A snapshot needs no handle to the
/// processes themselves, which is why it is used rather than OpenProcess:
/// an unelevated netwatch is refused a handle to most services and to other
/// users' processes, and the snapshot still names them. `Err` carries the
/// Win32 error.
pub fn process_names(pids: &HashSet<u32>) -> Result<HashMap<u32, String>, u32> {
    // SAFETY: takes no pointers; the handle it returns is checked below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        // SAFETY: reads this thread's last-error value, nothing else.
        return Err(unsafe { GetLastError() });
    }
    let mut names = HashMap::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: `snapshot` is the live handle just checked, and `entry` is a
    // writable PROCESSENTRY32W whose `dwSize` gives its true size.
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        if pids.contains(&entry.th32ProcessID) {
            let name = socket_table::image_name(&entry.szExeFile);
            if !name.is_empty() {
                names.insert(entry.th32ProcessID, name);
            }
        }
        // SAFETY: as for Process32FirstW above.
        more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    // SAFETY: `snapshot` is open, owned here, and closed exactly once.
    unsafe { CloseHandle(snapshot) };
    Ok(names)
}

/// One of the four `*_OWNER_PID` tables: a `dwNumEntries` count followed by
/// that many rows. The layouts are windows-sys's, from Microsoft's metadata;
/// this only names which row type each table holds and where its rows start.
trait OwnerPidTable {
    type Row: Copy;
    /// Byte offset of the first row, after the count and any padding.
    const ROWS_AT: usize;
    fn claimed(&self) -> u32;
}

macro_rules! owner_pid_table {
    ($table:ty, $row:ty) => {
        impl OwnerPidTable for $table {
            type Row = $row;
            const ROWS_AT: usize = offset_of!($table, table);
            fn claimed(&self) -> u32 {
                self.dwNumEntries
            }
        }
    };
}

owner_pid_table!(MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID);
owner_pid_table!(MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID);
owner_pid_table!(MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID);
owner_pid_table!(MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID);

/// NTSTATUS STATUS_UNSUCCESSFUL. GetExtendedTcpTable and GetExtendedUdpTable
/// return it, undocumented, in place of ERROR_INSUFFICIENT_BUFFER when the
/// table changes while they copy it (psutil#1294, retried since psutil#1335).
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

/// Read one table through the sizing exchange these calls share: offer a
/// buffer, and when it is too small the call writes the size it needs into
/// `size` and returns ERROR_INSUFFICIENT_BUFFER. Sockets opened between two
/// calls can outgrow the new size too, so the buffer is grown with some
/// headroom and the call tried a few times. The same race can surface as
/// STATUS_UNSUCCESSFUL, and the psutil report that found it also shows
/// ERROR_NOT_ENOUGH_MEMORY. Neither promises to write a size, so the buffer
/// grows from the larger of what was offered and what came back. Giving up
/// on them would send the whole tick to netstat on exactly the busy hosts
/// where spawning it costs the most.
fn read_table<T: OwnerPidTable>(
    call: impl Fn(*mut c_void, &mut u32) -> u32,
) -> Result<Vec<T::Row>, u32> {
    // Room for a few hundred rows, which covers most hosts in one call.
    let mut size: u32 = 16 * 1024;
    let mut last = NO_ERROR;
    for _ in 0..4 {
        // Never smaller than the table struct, so its count can be read.
        size = size.max(size_of::<T>() as u32);
        // u32 elements keep the buffer 4-byte aligned, which is all any
        // field in these tables needs.
        let mut buf = vec![0u32; (size as usize).div_ceil(4)];
        let mut filled = size;
        last = call(buf.as_mut_ptr().cast(), &mut filled);
        match last {
            NO_ERROR => return Ok(rows::<T>(&buf, filled as usize)),
            // .NET reads this as "no interfaces of this family", an empty
            // table rather than an error.
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_INSUFFICIENT_BUFFER | STATUS_UNSUCCESSFUL | ERROR_NOT_ENOUGH_MEMORY => {
                let need = size.max(filled);
                size = need.saturating_add(need / 8);
            }
            other => return Err(other),
        }
    }
    Err(last)
}

/// Copy the rows out of a buffer a successful call filled. `filled` is the
/// byte count the call left in its size argument, never trusted past the
/// buffer's own length. A buffer too short to hold the whole table struct,
/// its header and one row, has no rows: `read_table` never passes one, but
/// this is a safe fn and checks.
fn rows<T: OwnerPidTable>(buf: &[u32], filled: usize) -> Vec<T::Row> {
    // The tables' fields are all u32 and byte arrays, so u32 elements align
    // the buffer for them. Checked here rather than taken on trust.
    const { assert!(align_of::<T>() <= align_of::<u32>()) };
    if size_of_val(buf) < size_of::<T>() {
        return Vec::new();
    }
    let bytes = filled.min(size_of_val(buf));
    // SAFETY: the check above leaves at least `size_of::<T>()` bytes, the
    // assert above makes the u32 elements aligned for `T`, and a successful
    // call wrote a table header at the start.
    let claimed = unsafe { &*buf.as_ptr().cast::<T>() }.claimed();
    let n = socket_table::rows_that_fit(bytes, T::ROWS_AT, size_of::<T::Row>(), claimed as usize);
    // SAFETY: `ROWS_AT` is an offset inside `T`, and the buffer is never
    // smaller than `T`, so the pointer stays inside the allocation.
    let first = unsafe { buf.as_ptr().cast::<u8>().add(T::ROWS_AT) }.cast::<T::Row>();
    // SAFETY: `rows_that_fit` keeps all `n` rows inside the first `bytes`
    // bytes of `buf`. The rows are u32s and byte arrays, valid for any bit
    // pattern and 4-byte aligned like the buffer, and they are copied out
    // before `buf` is dropped.
    unsafe { std::slice::from_raw_parts(first, n) }.to_vec()
}

impl From<&MIB_TCPROW_OWNER_PID> for Tcp4Row {
    fn from(r: &MIB_TCPROW_OWNER_PID) -> Self {
        Tcp4Row {
            state: r.dwState,
            local_addr: r.dwLocalAddr,
            local_port: r.dwLocalPort,
            remote_addr: r.dwRemoteAddr,
            remote_port: r.dwRemotePort,
            owning_pid: r.dwOwningPid,
        }
    }
}

impl From<&MIB_TCP6ROW_OWNER_PID> for Tcp6Row {
    fn from(r: &MIB_TCP6ROW_OWNER_PID) -> Self {
        Tcp6Row {
            local_addr: r.ucLocalAddr,
            local_port: r.dwLocalPort,
            remote_addr: r.ucRemoteAddr,
            remote_port: r.dwRemotePort,
            state: r.dwState,
            owning_pid: r.dwOwningPid,
        }
    }
}

impl From<&MIB_UDPROW_OWNER_PID> for Udp4Row {
    fn from(r: &MIB_UDPROW_OWNER_PID) -> Self {
        Udp4Row {
            local_addr: r.dwLocalAddr,
            local_port: r.dwLocalPort,
            owning_pid: r.dwOwningPid,
        }
    }
}

impl From<&MIB_UDP6ROW_OWNER_PID> for Udp6Row {
    fn from(r: &MIB_UDP6ROW_OWNER_PID) -> Self {
        Udp6Row {
            local_addr: r.ucLocalAddr,
            local_port: r.dwLocalPort,
            owning_pid: r.dwOwningPid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING,
        MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
        MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN,
        MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT,
    };

    fn own_pid() -> Option<u32> {
        Some(std::process::id())
    }

    /// Runs `read_table` against a stand-in for GetExtendedTcpTable that
    /// answers with each `(code, size it writes back)` of `script` in turn,
    /// then succeeds with one row. Returns the rows and every size offered.
    fn scripted(script: &[(u32, Option<u32>)]) -> (Result<Vec<Tcp4Row>, u32>, Vec<u32>) {
        let offered = RefCell::new(Vec::new());
        let result = read_table::<MIB_TCPTABLE_OWNER_PID>(|buf, size| {
            let mut offered = offered.borrow_mut();
            offered.push(*size);
            if let Some(&(code, reported)) = script.get(offered.len() - 1) {
                if let Some(reported) = reported {
                    *size = reported;
                }
                return code;
            }
            // SAFETY: `read_table` offers at least a whole table, zeroed and
            // aligned for it, and this is the only reference to it.
            let table = unsafe { &mut *buf.cast::<MIB_TCPTABLE_OWNER_PID>() };
            table.dwNumEntries = 1;
            table.table[0] = MIB_TCPROW_OWNER_PID {
                dwState: MIB_TCP_STATE_ESTAB as u32,
                dwOwningPid: 42,
                ..Default::default()
            };
            NO_ERROR
        });
        let rows = result.map(|rows| rows.iter().map(Tcp4Row::from).collect());
        (rows, offered.into_inner())
    }

    fn the_row() -> Vec<Tcp4Row> {
        vec![Tcp4Row {
            state: MIB_TCP_STATE_ESTAB as u32,
            owning_pid: 42,
            ..Default::default()
        }]
    }

    /// A table that changes while it is copied can come back as the
    /// undocumented STATUS_UNSUCCESSFUL, or as ERROR_NOT_ENOUGH_MEMORY, with
    /// no size written or a zero one. Both are retried with a larger buffer,
    /// not handed up to send the whole tick to netstat.
    #[test]
    fn a_table_changing_mid_copy_is_read_again() {
        let (rows, offered) = scripted(&[
            (STATUS_UNSUCCESSFUL, None),
            (ERROR_NOT_ENOUGH_MEMORY, Some(0)),
        ]);
        assert_eq!(rows, Ok(the_row()));
        assert_eq!(offered.len(), 3);
        assert!(
            offered.windows(2).all(|w| w[1] > w[0]),
            "each retry offers more room: {offered:?}"
        );
    }

    /// `rows` is safe to call with any slice, so one shorter than the table
    /// struct must not have the struct borrowed past its end. Without the
    /// check, the empty slice reads its row count through a dangling pointer.
    /// A slice one u32 short of the struct holds a header but no row, so it
    /// reads none either way, but under Miri it fails a check that stops at
    /// the header.
    #[test]
    fn a_buffer_shorter_than_the_table_struct_reads_no_rows() {
        assert!(rows::<MIB_TCPTABLE_OWNER_PID>(&[], 0).is_empty());
        let short = vec![1u32; size_of::<MIB_TCP6TABLE_OWNER_PID>() / 4 - 1];
        assert!(rows::<MIB_TCP6TABLE_OWNER_PID>(&short, short.len() * 4).is_empty());
    }

    #[test]
    fn a_short_buffer_grows_past_the_size_the_call_asks_for() {
        let (rows, offered) = scripted(&[(ERROR_INSUFFICIENT_BUFFER, Some(100_000))]);
        assert_eq!(rows, Ok(the_row()));
        assert!(offered[1] >= 100_000, "offered {offered:?}");
    }

    /// .NET reads ERROR_NO_DATA as a family with no interfaces. Counting it
    /// as a failure would send all four tables to netstat on such a host on
    /// every tick.
    #[test]
    fn no_table_for_a_family_is_empty_not_a_failure() {
        let (rows, offered) = scripted(&[(ERROR_NO_DATA, None)]);
        assert_eq!(rows, Ok(Vec::new()));
        assert_eq!(offered.len(), 1);
    }

    #[test]
    fn a_hard_failure_or_a_race_that_never_settles_is_reported() {
        let (rows, offered) = scripted(&[(ERROR_INVALID_PARAMETER, None)]);
        assert_eq!(rows, Err(ERROR_INVALID_PARAMETER));
        assert_eq!(offered.len(), 1, "not retried");

        let (rows, offered) = scripted(&[(STATUS_UNSUCCESSFUL, None); 4]);
        assert_eq!(rows, Err(STATUS_UNSUCCESSFUL));
        assert_eq!(offered.len(), 4);
    }

    /// `tcp_state_name` matches on bare numbers so it can be tested off
    /// Windows; this ties each number to Microsoft's own constant.
    #[test]
    fn state_numbers_are_microsofts() {
        for (constant, name) in [
            (MIB_TCP_STATE_CLOSED, "CLOSED"),
            (MIB_TCP_STATE_LISTEN, "LISTEN"),
            (MIB_TCP_STATE_SYN_SENT, "SYN-SENT"),
            (MIB_TCP_STATE_SYN_RCVD, "SYN-RECV"),
            (MIB_TCP_STATE_ESTAB, "ESTABLISHED"),
            (MIB_TCP_STATE_FIN_WAIT1, "FIN-WAIT-1"),
            (MIB_TCP_STATE_FIN_WAIT2, "FIN-WAIT-2"),
            (MIB_TCP_STATE_CLOSE_WAIT, "CLOSE-WAIT"),
            (MIB_TCP_STATE_CLOSING, "CLOSING"),
            (MIB_TCP_STATE_LAST_ACK, "LAST-ACK"),
            (MIB_TCP_STATE_TIME_WAIT, "TIME-WAIT"),
            (MIB_TCP_STATE_DELETE_TCB, "CLOSED"),
        ] {
            assert_eq!(socket_table::tcp_state_name(constant as u32), name);
        }
    }

    /// A listener this test opens is in the table, under this process's pid,
    /// with the state and endpoints netwatch's other platforms would report.
    #[test]
    fn finds_its_own_tcp_listener_and_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let client_port = client.local_addr().unwrap().port();

        let sockets = sockets().expect("GetExtendedTcpTable");
        let local = format!("127.0.0.1:{port}");
        let listen = sockets
            .iter()
            .find(|s| s.protocol == "TCP" && s.local_addr == local && s.state == "LISTEN")
            .unwrap_or_else(|| panic!("no LISTEN row for {local}"));
        assert_eq!(listen.pid, own_pid());
        assert_eq!(listen.remote_addr, "*:*");

        let client_local = format!("127.0.0.1:{client_port}");
        let established = sockets
            .iter()
            .find(|s| s.protocol == "TCP" && s.local_addr == client_local)
            .unwrap_or_else(|| panic!("no row for the client end {client_local}"));
        assert_eq!(established.remote_addr, local);
        assert_eq!(established.state, "ESTABLISHED");
        assert_eq!(established.pid, own_pid());
    }

    #[test]
    fn finds_its_own_ipv6_listener() {
        let listener = TcpListener::bind("[::1]:0").expect("bind ::1");
        let port = listener.local_addr().unwrap().port();
        let local = format!("[::1]:{port}");
        let sockets = sockets().expect("GetExtendedTcpTable");
        let row = sockets
            .iter()
            .find(|s| s.protocol == "TCP" && s.local_addr == local)
            .unwrap_or_else(|| panic!("no row for {local}"));
        assert_eq!(row.state, "LISTEN");
        assert_eq!(row.pid, own_pid());
    }

    #[test]
    fn finds_its_own_udp_socket() {
        let v4 = UdpSocket::bind("127.0.0.1:0").expect("bind 127.0.0.1");
        let v6 = UdpSocket::bind("[::1]:0").expect("bind ::1");
        let sockets = sockets().expect("GetExtendedUdpTable");
        for local in [
            format!("127.0.0.1:{}", v4.local_addr().unwrap().port()),
            format!("[::1]:{}", v6.local_addr().unwrap().port()),
        ] {
            let row = sockets
                .iter()
                .find(|s| s.protocol == "UDP" && s.local_addr == local)
                .unwrap_or_else(|| panic!("no UDP row for {local}"));
            assert_eq!(row.pid, own_pid());
            assert_eq!(row.remote_addr, "*:*");
            assert_eq!(row.state, "");
        }
    }

    /// The test binary is `netwatch-<hash>.exe`; the snapshot must name it as
    /// tasklist would, and leave out pids nobody asked for.
    #[test]
    fn names_its_own_process() {
        let pid = std::process::id();
        let names = process_names(&HashSet::from([pid])).expect("Toolhelp32 snapshot");
        let name = names.get(&pid).expect("own pid named");
        assert!(
            name.starts_with("netwatch") && name.ends_with(".exe"),
            "expected the test binary's image name, got {name:?}"
        );
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn no_pids_asked_for_names_none() {
        assert!(process_names(&HashSet::new()).unwrap().is_empty());
    }
}
