//! HTTP over the mesh, for anyone on it.
//!
//! Every peer is a stranger, so everything a peer can make this service do
//! has a bound: how many connections at once in all and from one address,
//! how long its header may take and how large it may be, how long a
//! connection may last. A request names this exit in its `Host` header or
//! is refused: a page on some other site must not be able to read what
//! this one says to a browser on the mesh.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::config::Config;
use crate::terms::{self, Exit};

/// How much a peer may have of this service.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Connections at once, in all and from one address.
    pub connections: usize,
    pub per_peer: usize,
    /// The time a request's header has to arrive, and a connection's whole
    /// life.
    pub header_time: Duration,
    pub lifetime: Duration,
    /// The most a request's header may be, in bytes.
    pub header_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connections: 64,
            per_peer: 8,
            header_time: Duration::from_secs(5),
            lifetime: Duration::from_secs(60),
            header_bytes: 16 * 1024,
        }
    }
}

/// What every request is answered from.
pub struct Site {
    pub config: Config,
    pub exit: Exit,
    /// The `Host` headers this exit answers to, in small letters.
    pub hosts: Vec<String>,
}

impl Site {
    pub fn new(config: Config, exit: Exit) -> Site {
        let port = config.port;
        let mut hosts = vec![format!("[{}]:{port}", exit.address)];
        if let Some(npub) = &exit.npub {
            hosts.push(format!("{npub}.fips:{port}"));
        }
        let hosts = hosts.into_iter().map(|host| host.to_ascii_lowercase()).collect();
        Site { config, exit, hosts }
    }
}

/// Is `peer` someone this service talks to: a node of the mesh? It listens
/// on the mesh address only, so nobody else should be here; this is said
/// again rather than trusted to the address it is bound to.
pub fn on_the_mesh(peer: IpAddr) -> bool {
    matches!(peer, IpAddr::V6(addr) if addr.octets()[0] == 0xfd)
}

fn answer(status: StatusCode, kind: &'static str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    response
}

fn plain(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    answer(status, "text/plain; charset=utf-8", format!("{text}\n"))
}

/// One request, from `peer`.
pub fn respond<B>(site: &Site, peer: Ipv6Addr, request: &Request<B>) -> Response<Full<Bytes>> {
    let host = request.headers().get(header::HOST).and_then(|host| host.to_str().ok()).map(str::to_ascii_lowercase);
    match host {
        Some(host) if site.hosts.contains(&host) => {}
        _ => return plain(StatusCode::MISDIRECTED_REQUEST, "not this exit's name"),
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        let mut refused = plain(StatusCode::METHOD_NOT_ALLOWED, "only GET, for now");
        refused.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return refused;
    }
    let terms = || terms::terms(&site.config, &site.exit, peer);
    let mut response = match request.uri().path() {
        "/v1/terms" => match serde_json::to_vec(&terms()) {
            Ok(json) => answer(StatusCode::OK, "application/json", json),
            Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "the terms could not be written"),
        },
        "/" => answer(StatusCode::OK, "text/html; charset=utf-8", terms::page(&terms())),
        "/style.css" => answer(StatusCode::OK, "text/css; charset=utf-8", terms::STYLE),
        _ => plain(StatusCode::NOT_FOUND, "nothing here"),
    };
    if request.method() == Method::HEAD {
        *response.body_mut() = Full::new(Bytes::new());
    }
    response
}

/// A place among the connections of one peer, given back when it is dropped.
struct PeerPlace {
    peers: Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer: IpAddr,
}

impl PeerPlace {
    fn take(peers: &Arc<Mutex<HashMap<IpAddr, usize>>>, peer: IpAddr, most: usize) -> Option<PeerPlace> {
        let mut count = peers.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let its = count.entry(peer).or_insert(0);
        if *its >= most {
            return None;
        }
        *its += 1;
        Some(PeerPlace { peers: peers.clone(), peer })
    }
}

impl Drop for PeerPlace {
    fn drop(&mut self) {
        let mut count = self.peers.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(its) = count.get_mut(&self.peer) {
            *its -= 1;
            if *its == 0 {
                count.remove(&self.peer);
            }
        }
    }
}

/// Serve `listener` for as long as it accepts. `admit` says which peers are
/// talked to at all ([`on_the_mesh`], except in tests); one that is not is
/// closed without a word, and so is one more than the limits allow.
pub async fn serve(listener: TcpListener, site: Arc<Site>, limits: Limits, admit: fn(IpAddr) -> bool) {
    let all = Arc::new(Semaphore::new(limits.connections));
    let peers: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::default();
    loop {
        let (stream, from): (_, SocketAddr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Out of descriptors, for instance: said, and tried again.
                eprintln!("fips-exit-payd: accept: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let peer = from.ip();
        if !admit(peer) {
            continue;
        }
        let Ok(place) = all.clone().try_acquire_owned() else { continue };
        let Some(peer_place) = PeerPlace::take(&peers, peer, limits.per_peer) else { continue };
        let mesh_peer = match peer {
            IpAddr::V6(addr) => addr,
            IpAddr::V4(addr) => addr.to_ipv6_mapped(),
        };
        let site = site.clone();
        tokio::spawn(async move {
            let _places = (place, peer_place);
            let service = service_fn(move |request: Request<Incoming>| {
                let response = respond(&site, mesh_peer, &request);
                async move { Ok::<_, Infallible>(response) }
            });
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_time)
                .max_buf_size(limits.header_bytes.max(8192))
                .serve_connection(TokioIo::new(stream), service);
            let _ = tokio::time::timeout(limits.lifetime, connection).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn site() -> Arc<Site> {
        let config = crate::config::Config::from_settings(&crate::config::settings(
            "ACCESS=paid\nPRICE_MSAT_PER_GB=2000000\nPACKAGES=1gb:1GB:1500:30\nPAY_PORT=5170\n",
        ))
        .unwrap()
        .unwrap();
        let exit = Exit {
            npub: Some("npub1Example".into()),
            address: "fd14::1".parse().unwrap(),
            name: "An exit".into(),
            about: String::new(),
            country: None,
        };
        Arc::new(Site::new(config, exit))
    }

    fn get(path: &str, host: &str) -> Request<()> {
        Request::builder().uri(path).header(header::HOST, host).body(()).unwrap()
    }

    #[test]
    fn a_request_names_this_exit_or_is_refused() {
        let site = site();
        let peer = "fd99::2".parse().unwrap();
        for host in ["[fd14::1]:5170", "[FD14::1]:5170", "npub1example.fips:5170", "NPUB1EXAMPLE.FIPS:5170"] {
            assert_eq!(respond(&site, peer, &get("/v1/terms", host)).status(), StatusCode::OK, "{host}");
        }
        for host in
            ["[fd14::1]", "[fd14::1]:80", "fd14::1:5170", "evil.example", "npub1example.fips", "localhost:5170", ""]
        {
            assert_eq!(
                respond(&site, peer, &get("/v1/terms", host)).status(),
                StatusCode::MISDIRECTED_REQUEST,
                "{host}"
            );
        }
        let no_host = Request::builder().uri("/v1/terms").body(()).unwrap();
        assert_eq!(respond(&site, peer, &no_host).status(), StatusCode::MISDIRECTED_REQUEST);
    }

    #[test]
    fn what_there_is_and_what_there_is_not() {
        let (site, peer, host) = (site(), "fd99::2".parse().unwrap(), "[fd14::1]:5170");
        let terms = respond(&site, peer, &get("/v1/terms", host));
        assert_eq!(terms.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(terms.headers()[header::CACHE_CONTROL], "no-store");
        let page = respond(&site, peer, &get("/", host));
        assert_eq!(page.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert!(page.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().starts_with("default-src 'none'"));
        assert_eq!(respond(&site, peer, &get("/style.css", host)).status(), StatusCode::OK);
        for path in ["/v1/terms/", "/v2/terms", "/index.html", "/../etc/passwd", "/v1/orders"] {
            assert_eq!(respond(&site, peer, &get(path, host)).status(), StatusCode::NOT_FOUND, "{path}");
        }
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
            let request =
                Request::builder().method(method.clone()).uri("/v1/terms").header(header::HOST, host).body(()).unwrap();
            let response = respond(&site, peer, &request);
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
            assert_eq!(response.headers()[header::ALLOW], "GET, HEAD");
        }
    }

    #[test]
    fn only_the_mesh_is_talked_to() {
        for peer in ["fd00::1", "fd99:8877::2"] {
            assert!(on_the_mesh(peer.parse().unwrap()), "{peer}");
        }
        for peer in ["::1", "fe80::1", "fc00::1", "2001:db8::1", "::ffff:10.0.0.1", "10.0.0.1", "127.0.0.1"] {
            assert!(!on_the_mesh(peer.parse().unwrap()), "{peer}");
        }
    }

    /// A whole exchange over a socket: the server as it runs, with the
    /// loopback address let in instead of the mesh.
    async fn server(limits: Limits, admit: fn(IpAddr) -> bool) -> SocketAddr {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, site(), limits, admit));
        at
    }

    async fn exchange(at: SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(at).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await;
        String::from_utf8_lossy(&answer).into_owned()
    }

    #[tokio::test]
    async fn the_terms_over_a_socket_say_who_asked() {
        let at = server(Limits::default(), |_| true).await;
        let answer = exchange(at, b"GET /v1/terms HTTP/1.1\r\nHost: [fd14::1]:5170\r\nConnection: close\r\n\r\n").await;
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        let body = answer.split("\r\n\r\n").nth(1).unwrap();
        let terms: serde_json::Value = serde_json::from_str(body).unwrap();
        // Loopback, as an IPv6 address: in use, the mesh address of the caller.
        assert_eq!(terms["you"]["address"], "::1");
        assert_eq!(terms["price_msat_per_gb"], 2_000_000);
        assert_eq!(terms["methods"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn a_peer_off_the_mesh_gets_nothing() {
        let at = server(Limits::default(), on_the_mesh).await;
        let answer = exchange(at, b"GET /v1/terms HTTP/1.1\r\nHost: [fd14::1]:5170\r\nConnection: close\r\n\r\n").await;
        assert_eq!(answer, "", "closed without a word");
    }

    #[tokio::test]
    async fn a_header_too_large_or_too_slow_ends_the_connection() {
        let limits = Limits { header_time: Duration::from_millis(500), ..Limits::default() };
        let at = server(limits, |_| true).await;
        let mut big = b"GET /v1/terms HTTP/1.1\r\nHost: [fd14::1]:5170\r\nX-Filler: ".to_vec();
        big.extend(std::iter::repeat_n(b'x', 40_000));
        big.extend_from_slice(b"\r\n\r\n");
        let answer = exchange(at, &big).await;
        assert!(answer.starts_with("HTTP/1.1 431"), "{answer:.60}");
        // Half a header, and then nothing: closed when its time is up.
        let started = std::time::Instant::now();
        let mut stream = TcpStream::connect(at).await.unwrap();
        stream.write_all(b"GET /v1/terms HTTP/1.1\r\nHost: [fd").await.unwrap();
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest)).await;
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn one_peer_has_only_so_many_connections() {
        let limits = Limits { per_peer: 2, ..Limits::default() };
        let at = server(limits, |_| true).await;
        // Two that stay open and say nothing.
        let held = [TcpStream::connect(at).await.unwrap(), TcpStream::connect(at).await.unwrap()];
        tokio::time::sleep(Duration::from_millis(200)).await;
        let third = exchange(at, b"GET /v1/terms HTTP/1.1\r\nHost: [fd14::1]:5170\r\nConnection: close\r\n\r\n").await;
        assert_eq!(third, "", "a third from the same address is closed");
        drop(held);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let again = exchange(at, b"GET /v1/terms HTTP/1.1\r\nHost: [fd14::1]:5170\r\nConnection: close\r\n\r\n").await;
        assert!(again.starts_with("HTTP/1.1 200"), "places are given back: {again:.40}");
    }
}
