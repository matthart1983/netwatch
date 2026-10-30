//! Bounded, cancellable I/O shared by diagnostic probes. Linux NSS resolution
//! runs in a killable child; other platforms share one native resolver worker.
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
#[derive(Clone, Default)]
pub struct Cancel(pub Arc<AtomicBool>);
impl Cancel {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    pub fn check(&self, deadline: Instant) -> io::Result<()> {
        if self.cancelled() {
            Err(io::Error::other("probe cancelled"))
        } else if Instant::now() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe deadline exceeded",
            ))
        } else {
            Ok(())
        }
    }
}
#[cfg(unix)]
pub fn command(
    program: &str,
    args: &[&str],
    timeout: Duration,
    cancel: &Cancel,
) -> io::Result<(bool, String)> {
    let deadline = Instant::now() + timeout;
    cancel.check(deadline)?;
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: `stdout` and `stderr` are this process's ends of the child's
        // two pipes, owned here and open for the whole block. F_SETFL with
        // O_NONBLOCK takes integers only and changes the status flags of
        // those two pipe ends and nothing else.
        let rc = unsafe {
            let a = nix::libc::fcntl(
                stdout.as_raw_fd(),
                nix::libc::F_SETFL,
                nix::libc::O_NONBLOCK,
            );
            let b = nix::libc::fcntl(
                stderr.as_raw_fd(),
                nix::libc::F_SETFL,
                nix::libc::O_NONBLOCK,
            );
            a.min(b)
        };
        if rc == -1 {
            let e = io::Error::last_os_error();
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    }
    let result = (|| {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            cancel.check(deadline)?;
            let status = child.try_wait()?;
            for pipe in [&mut stdout as &mut dyn Read, &mut stderr as &mut dyn Read] {
                loop {
                    match pipe.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            out.extend_from_slice(&buf[..n]);
                            if out.len() > 65536 {
                                return Err(io::Error::other("probe output exceeds 64 KiB"));
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }
            if let Some(status) = status {
                return Ok((status.success(), String::from_utf8_lossy(&out).into_owned()));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}
#[cfg(not(unix))]
pub fn command(
    _program: &str,
    _args: &[&str],
    _timeout: Duration,
    _cancel: &Cancel,
) -> io::Result<(bool, String)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bounded probe subprocesses require Unix",
    ))
}
pub fn resolve(host: &str, port: u16, cancel: &Cancel) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if host.starts_with('-') || host.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid host"));
    }
    #[cfg(not(target_os = "linux"))]
    {
        native_resolve(host, port, cancel)
    }
    #[cfg(target_os = "linux")]
    {
        let (ok, output) = command("getent", &["ahosts", host], Duration::from_secs(3), cancel)?;
        if !ok {
            return Err(io::Error::other(
                "system NSS lookup failed; inspect resolver results",
            ));
        }
        let mut addrs = Vec::new();
        for line in output.lines() {
            if let Some(ip) = line
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<IpAddr>().ok())
            {
                let addr = SocketAddr::new(ip, port);
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
                if addrs.len() == 16 {
                    break;
                }
            }
        }
        if addrs.is_empty() {
            Err(io::Error::other("system lookup returned no addresses"))
        } else {
            Ok(addrs)
        }
    }
}

/// Other platforms retain their native name-service semantics without requiring
/// Linux's getent. At most one resolver call and one queued request exist. The
/// caller can time out/cancel even if the OS resolver itself cannot be cancelled.
#[cfg(any(not(target_os = "linux"), test))]
fn native_resolve(host: &str, port: u16, cancel: &Cancel) -> io::Result<Vec<SocketAddr>> {
    use std::{
        net::ToSocketAddrs,
        sync::{mpsc, OnceLock},
    };
    struct Request {
        host: String,
        port: u16,
        cancel: Cancel,
        deadline: Instant,
        reply: mpsc::SyncSender<io::Result<Vec<SocketAddr>>>,
    }
    static QUEUE: OnceLock<mpsc::SyncSender<Request>> = OnceLock::new();
    let sender = QUEUE.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<Request>(1);
        std::thread::spawn(move || {
            while let Ok(r) = rx.recv() {
                if r.cancel.check(r.deadline).is_err() {
                    continue;
                }
                let answer = (r.host.as_str(), r.port)
                    .to_socket_addrs()
                    .map(|a| a.take(16).collect());
                let _ = r.reply.send(answer);
            }
        });
        tx
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    cancel.check(deadline)?;
    let (reply, receiver) = mpsc::sync_channel(1);
    sender
        .try_send(Request {
            host: host.into(),
            port,
            cancel: cancel.clone(),
            deadline,
            reply,
        })
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "native resolver busy"))?;
    loop {
        cancel.check(deadline)?;
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(r) => return r,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => return Err(io::Error::other("native resolver unavailable")),
        }
    }
}

pub struct Stream {
    pub tcp: TcpStream,
    pub deadline: Instant,
    pub cancel: Cancel,
}
impl Stream {
    pub fn new(tcp: TcpStream, deadline: Instant, cancel: Cancel) -> io::Result<Self> {
        tcp.set_read_timeout(Some(Duration::from_millis(200)))?;
        tcp.set_write_timeout(Some(Duration::from_millis(200)))?;
        Ok(Self {
            tcp,
            deadline,
            cancel,
        })
    }
}
impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            self.cancel.check(self.deadline)?;
            match self.tcp.read(buf) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                r => return r,
            }
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            self.cancel.check(self.deadline)?;
            match self.tcp.write(buf) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                r => return r,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.cancel.check(self.deadline)?;
        self.tcp.flush()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn portable_resolver_keeps_native_localhost_semantics_and_cancellation() {
        let c = Cancel::default();
        assert!(native_resolve("localhost", 80, &c)
            .unwrap()
            .iter()
            .all(|a| a.ip().is_loopback()));
        c.cancel();
        assert!(native_resolve("localhost", 80, &c).is_err());
    }

    #[test]
    fn subprocess_deadline_and_cancel_are_bounded() {
        let start = Instant::now();
        assert!(command(
            "sleep",
            &["10"],
            Duration::from_millis(80),
            &Cancel::default()
        )
        .is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        let c = Cancel::default();
        c.cancel();
        assert!(resolve("example.invalid", 80, &c).is_err());
    }
    #[test]
    fn cancelled_stream_does_not_wait_for_peer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let c = Cancel::default();
        let mut s = Stream::new(tcp, Instant::now() + Duration::from_secs(10), c.clone()).unwrap();
        c.cancel();
        assert!(s.read(&mut [0]).is_err());
    }
}
