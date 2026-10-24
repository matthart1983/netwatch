//! The HTTP client shared by the remote publisher, the geo and whois
//! lookups and the Ollama insights call.
//!
//! ureq's default agent has no read or write timeout, so a server that
//! accepts the connection and then goes quiet holds the calling thread
//! forever. For the one geo or whois worker that means every later lookup
//! stalls behind it; for the remote sender it means the daemon's shutdown
//! drain never returns. Requests built from [`agent`] give up instead.
//!
//! Where ureq 3's defaults differ from what ureq 2 did here, [`build`] sets
//! the old behaviour by hand: no proxy from the environment, the same
//! redirect limit, and 4xx and 5xx statuses as errors. [`read_text`] keeps
//! ureq 2's cap on decompressed text.

use std::sync::OnceLock;
use std::time::Duration;

/// How long to wait for the connection to be established, the TLS handshake
/// included, and each of the handshake's reads and writes is bounded by
/// [`IO_TIMEOUT`] as well. Name resolution comes first and has no limit of
/// its own. ureq 2 could not interrupt the system resolver either.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long any single read or write may wait on the peer.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a response body may take to arrive once its head has, the body
/// of a redirect included. ureq 3 reads a redirect's body to the end before
/// following it, where ureq 2 dropped it unread, so without this a 3xx that
/// streams forever holds the caller forever, at line rate.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// The most text [`read_text`] takes from one body, counted after gzip is
/// undone, as ureq 2 counted it.
pub const MAX_TEXT: u64 = 10 * 1024 * 1024;

/// Redirects followed before the request fails with `TooManyRedirects`.
/// ureq 2's limit of 5 counted the response that broke it, so it followed
/// four; ureq 3 counts only the redirects it follows.
const MAX_REDIRECTS: u32 = 4;

/// The shared agent. Built once, so its connection pool is shared too.
pub fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| build(CONNECT_TIMEOUT, IO_TIMEOUT, BODY_TIMEOUT))
}

/// GET `url` through the shared agent and read the body as text, up to
/// [`MAX_TEXT`]. A 4xx or 5xx answer is an error, the same as a connection
/// that fails.
pub fn get_text(url: &str) -> Result<String, ureq::Error> {
    read_text(agent().get(url).call()?.into_body())
}

/// Read a response body as text, up to [`MAX_TEXT`] bytes of it.
///
/// Not ureq 3's `read_to_string`: its 10 MiB limit counts the bytes on the
/// wire, before gzip is undone, and ureq decodes gzip whenever the response
/// says it is. 10 MiB of compressed zeros would come out as some 10 GiB of
/// `String`. Both are capped here: the wire bytes, so a stream of empty gzip
/// members cannot run on, and the text, so it cannot outgrow the limit.
pub fn read_text(body: ureq::Body) -> Result<String, ureq::Error> {
    use std::io::Read;
    let mut text = Vec::new();
    body.into_with_config()
        .limit(MAX_TEXT)
        .lossy_utf8(true)
        .reader()
        .take(MAX_TEXT + 1)
        .read_to_end(&mut text)?;
    if text.len() as u64 > MAX_TEXT {
        return Err(ureq::Error::BodyExceedsLimit(MAX_TEXT));
    }
    String::from_utf8(text)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e).into())
}

fn build(connect: Duration, io: Duration, body: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(connect))
        .timeout_per_read(Some(io))
        .timeout_per_write(Some(io))
        .timeout_recv_body(Some(body))
        // ureq 3 reads HTTP_PROXY, HTTPS_PROXY and ALL_PROXY by default;
        // ureq 2, built without its proxy-from-env feature, did not. Every
        // request here goes direct, as it always has.
        .proxy(None)
        .max_redirects(MAX_REDIRECTS)
        // Callers rely on this: the remote publisher classifies the status
        // carried by `Error::StatusCode`, and geo and whois treat any error
        // as no answer.
        .http_status_as_error(true)
        .build()
        .new_agent()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    /// Answer `n` connections with `response`, one request each, and return
    /// how many requests arrived.
    fn serve(
        n: usize,
        response: impl Fn(u16) -> String + Send + 'static,
    ) -> (String, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut seen = 0;
            for stream in listener.incoming().take(n) {
                let mut stream: TcpStream = stream.unwrap();
                read_head(&mut stream);
                seen += 1;
                let _ = stream.write_all(response(port).as_bytes());
            }
            seen
        });
        (format!("http://127.0.0.1:{port}/"), handle)
    }

    fn read_head(stream: &mut TcpStream) {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
            buf.push(byte[0]);
        }
    }

    /// A server that accepts and then never answers. Without a read timeout
    /// the request below would never return.
    #[test]
    fn a_silent_server_times_out_instead_of_hanging() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let _silent = std::thread::spawn(move || {
            let held: Vec<_> = listener.incoming().take(1).collect();
            std::thread::sleep(Duration::from_secs(5));
            drop(held);
        });

        let started = Instant::now();
        let result = build(CONNECT_TIMEOUT, Duration::from_millis(200), BODY_TIMEOUT)
            .get(&url)
            .call();
        assert!(
            matches!(result, Err(ureq::Error::Timeout(ureq::Timeout::PerRead))),
            "{result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn an_error_status_is_an_error_carrying_the_code() {
        let (url, server) = serve(1, |_| {
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .into()
        });
        let result = get_text(&url);
        assert!(
            matches!(result, Err(ureq::Error::StatusCode(503))),
            "{result:?}"
        );
        assert_eq!(server.join().unwrap(), 1);
    }

    #[test]
    fn a_body_is_read_as_text() {
        let (url, server) = serve(1, |_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}"
                .into()
        });
        assert_eq!(get_text(&url).unwrap(), "{\"status\":\"ok\"}");
        server.join().unwrap();
    }

    /// The same limit ureq 2 had: four redirects followed, and the fifth
    /// redirect response is an error rather than a sixth request.
    #[test]
    fn redirects_stop_where_they_did_under_ureq_2() {
        let (url, server) = serve(5, |port| {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/again\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        });
        let result = agent().get(&url).call();
        assert!(
            matches!(result, Err(ureq::Error::TooManyRedirects)),
            "{result:?}"
        );
        assert_eq!(server.join().unwrap(), 5);
    }

    /// A gzip body that inflates past the limit. ureq 3's own
    /// `read_to_string` counts only the compressed bytes and would hand back
    /// all of it.
    #[test]
    fn a_body_is_capped_after_it_is_decompressed() {
        use flate2::{write::GzEncoder, Compression};
        let mut gz = GzEncoder::new(Vec::new(), Compression::best());
        gz.write_all(&vec![b' '; MAX_TEXT as usize + 1024]).unwrap();
        let gz = gz.finish().unwrap();
        assert!(gz.len() < 1 << 20, "{} bytes compressed", gz.len());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_head(&mut stream);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                gz.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&gz);
        });
        let result = get_text(&url);
        assert!(
            matches!(result, Err(ureq::Error::BodyExceedsLimit(MAX_TEXT))),
            "{:?}",
            result.map(|s| s.len())
        );
        server.join().unwrap();
    }

    /// A redirect whose body never ends. ureq 3 reads it all before
    /// following the redirect; the body timeout stops it.
    #[test]
    fn an_endless_redirect_body_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_head(&mut stream);
            let head = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{addr}/next\r\n\
                 Transfer-Encoding: chunked\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes());
            let chunk = [b"4000\r\n".as_slice(), &[b'x'; 0x4000], b"\r\n"].concat();
            while stream.write_all(&chunk).is_ok() {}
        });

        let started = Instant::now();
        let result = build(CONNECT_TIMEOUT, IO_TIMEOUT, Duration::from_millis(300))
            .get(&format!("http://{addr}/"))
            .call();
        assert!(
            matches!(result, Err(ureq::Error::Timeout(ureq::Timeout::RecvBody))),
            "{result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(agent().config().timeouts().recv_body, Some(BODY_TIMEOUT));
    }

    /// ureq 3 would pick up a proxy from the environment by default. Checked
    /// on the configuration, since setting a proxy variable here would leak
    /// into every other test in the process.
    #[test]
    fn the_environment_proxy_is_not_used() {
        assert!(agent().config().proxy().is_none());
    }
}
