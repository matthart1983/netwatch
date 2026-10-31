//! Linux smoke check using a disposable sentinel, never real credentials.
//! Applies strict policy on the actual probe worker; parent cleans up the fixture.
//! The probe worker is a parser, so strict also needs Linux 6.7 or newer.
#![allow(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("sandbox_smoke is Linux-only");
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use netwatch::sandbox::{worker, Mode, SandboxPaths};
    let root =
        std::env::temp_dir().join(format!("netwatch-sandbox-smoke-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("sentinel"), b"test-only")?;
    let paths = SandboxPaths {
        cache_dir: Some(root.join("cache")),
        cwd: Some(root.join("exports")),
        ..Default::default()
    };
    paths.prepare()?;
    worker::install(Mode::Strict, paths).map_err(anyhow::Error::msg)?;
    let sentinel = root.join("sentinel");
    let exports = root.join("exports");
    // Bound here, outside the worker's domain.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    let tcp_addr = tcp.local_addr()?;
    let udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let udp_addr = udp.local_addr()?;
    worker::spawn("smoke", move || {
        assert_eq!(
            std::fs::read(sentinel).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::write(exports.join("allowed"), b"test-only").unwrap();
        // SAFETY: socket takes three integers and reads no memory of ours; the
        // descriptor it returns is checked below.
        let sock = unsafe {
            nix::libc::socket(
                nix::libc::AF_INET,
                nix::libc::SOCK_RAW,
                nix::libc::IPPROTO_ICMP,
            )
        };
        if sock >= 0 {
            // SAFETY: `sock` is the descriptor socket just returned, checked
            // non-negative above, owned by nothing else and not used again.
            unsafe {
                nix::libc::close(sock);
            }
            panic!("raw socket remained available under strict policy");
        }
        assert_eq!(
            std::net::TcpStream::connect(tcp_addr)
                .unwrap_err()
                .raw_os_error(),
            Some(nix::libc::EACCES),
            "TCP connect remained available to a parser worker"
        );
        // Landlock does not mediate UDP; the threat model says so.
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"test-only", udp_addr)
            .unwrap();
    })
    .join()
    .expect("probe worker panicked");
    let result = worker::wait_ready(std::time::Duration::from_secs(1));
    println!("{}", worker::summary());
    // A worker strict refused never ran, so it sent nothing.
    if result.is_ok() {
        udp.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        let mut datagram = [0; 16];
        let (received, _) = udp.recv_from(&mut datagram)?;
        assert_eq!(&datagram[..received], b"test-only");
    }
    std::fs::remove_dir_all(root)?;
    result.map_err(anyhow::Error::msg)
}
