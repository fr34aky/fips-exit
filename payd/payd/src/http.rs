//! HTTP over the mesh, for anyone on it.
//!
//! Every peer is a stranger, so everything a peer can make this service do
//! has a bound: how many connections at once in all and from one address,
//! how long its header may take and how large it may be, how long a
//! connection may last, how large its body may be. A request names this
//! exit in its `Host` header or is refused: a page on some other site must
//! not be able to read what this one says to a browser on the mesh. A
//! request that changes something comes from this exit's own page (its
//! `Origin`), or is JSON, which a page elsewhere cannot send here without
//! asking first, and is not let.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};

use crate::config::Config;
use crate::store::Store;
use crate::sync::{Seats, unix_now};
use crate::terms::{self, Exit, YourPackage};

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
    /// The most a request's header may be, in bytes, and its body.
    pub header_bytes: usize,
    pub body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connections: 64,
            per_peer: 8,
            header_time: Duration::from_secs(5),
            lifetime: Duration::from_secs(60),
            header_bytes: 16 * 1024,
            body_bytes: 8 * 1024,
        }
    }
}

/// What every request is answered from.
pub struct Site {
    pub config: Config,
    pub exit: Exit,
    /// The `Host` headers this exit answers to, in small letters.
    pub hosts: Vec<String>,
    /// The one `Origin` a form may come from: this exit's page.
    pub origin: String,
    pub store: Arc<Store>,
    pub seats: Seats,
    /// Told when a package changed, so that the daemon is told at once.
    pub changed: Arc<Notify>,
}

impl Site {
    pub fn new(config: Config, exit: Exit, store: Arc<Store>, seats: Seats, changed: Arc<Notify>) -> Site {
        // The exit's name, and nothing else: its fips address is reached
        // only by way of that name, which a browser then sends.
        let name = format!("{}.fips:{}", exit.npub, config.port).to_ascii_lowercase();
        let origin = format!("http://{name}");
        Site { config, exit, hosts: vec![name], origin, store, seats, changed }
    }

    /// The package `caller` is in, as the caller may see it.
    fn package_of(&self, caller: Ipv6Addr) -> Option<YourPackage> {
        let package = self.store.package_of(caller).ok().flatten()?;
        let seat = self.seats.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&caller).cloned();
        Some(YourPackage {
            id: package.id.clone(),
            standing: package.standing(unix_now()).word().to_string(),
            bytes_left: package.left(),
            until: (package.until != 0).then_some(package.until),
            members: package.members.len(),
            ipv4: seat.as_deref() != Some("no4"),
        })
    }
}

/// Is `peer` someone this service talks to: a node of the mesh? It listens
/// on the mesh address only, so nobody else should be here; this is said
/// again rather than trusted to the address it is bound to.
pub fn on_the_mesh(peer: IpAddr) -> bool {
    matches!(peer, IpAddr::V6(addr) if addr.octets()[0] == 0xfd)
}

pub fn answer(status: StatusCode, kind: &'static str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
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

/// The media type of a request's body, without its parameters, in small
/// letters.
fn media_type<B>(request: &Request<B>) -> String {
    let named = request.headers().get(header::CONTENT_TYPE).and_then(|kind| kind.to_str().ok()).unwrap_or("");
    named.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// Did the request come from this exit's own page? A browser says where a
/// request it sends comes from (`Origin`, and `Sec-Fetch-Site`); one that
/// says nothing is not believed to come from here.
fn from_this_page<B>(site: &Site, request: &Request<B>) -> bool {
    let said = |name: &str| request.headers().get(name).and_then(|value| value.to_str().ok());
    let origin_ours = said("origin").is_some_and(|origin| origin.eq_ignore_ascii_case(&site.origin));
    origin_ours && said("sec-fetch-site").is_none_or(|site| site == "same-origin")
}

/// Not from another site: a JSON request may come from a program, which
/// says no origin, or from this page; not from a page elsewhere.
fn not_from_elsewhere<B>(site: &Site, request: &Request<B>) -> bool {
    let said = |name: &str| request.headers().get(name).and_then(|value| value.to_str().ok());
    said("origin").is_none_or(|origin| origin.eq_ignore_ascii_case(&site.origin))
        && said("sec-fetch-site").is_none_or(|site| site == "same-origin" || site == "none")
}

/// One request, from `peer`, with its body.
pub fn respond<B>(site: &Site, peer: Ipv6Addr, request: &Request<B>, body: &[u8]) -> Response<Full<Bytes>> {
    let host = request.headers().get(header::HOST).and_then(|host| host.to_str().ok()).map(str::to_ascii_lowercase);
    match host {
        Some(host) if site.hosts.contains(&host) => {}
        _ => return plain(StatusCode::MISDIRECTED_REQUEST, "not this exit's name"),
    }
    let path = request.uri().path();
    let method = request.method();
    let reading = method == Method::GET || method == Method::HEAD;
    let terms = || terms::terms(&site.config, &site.exit, peer, site.package_of(peer));
    let refused = |allow: &'static str| {
        let mut refused = plain(StatusCode::METHOD_NOT_ALLOWED, &format!("only {allow} here"));
        refused.headers_mut().insert(header::ALLOW, HeaderValue::from_static(allow));
        refused
    };
    // A HEAD is answered as a GET; hyper sends the head of it and not the body.
    match path {
        "/v1/terms" | "/" | "/style.css" if !reading => refused("GET, HEAD"),
        "/v1/terms" => match serde_json::to_vec(&terms()) {
            Ok(json) => answer(StatusCode::OK, "application/json", json),
            Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "the terms could not be written"),
        },
        "/" => answer(StatusCode::OK, "text/html; charset=utf-8", terms::page(&terms())),
        "/style.css" => answer(StatusCode::OK, "text/css; charset=utf-8", terms::STYLE),
        "/v1/package" | "/v1/package/members" | "/v1/leave" | "/package" | "/package/members" | "/leave"
            if method != Method::POST =>
        {
            refused("POST")
        }
        "/v1/package" | "/v1/package/members" | "/v1/leave" => {
            if media_type(request) != "application/json" {
                plain(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON, as application/json")
            } else if !not_from_elsewhere(site, request) {
                plain(StatusCode::FORBIDDEN, "not from another site")
            } else {
                crate::manage::as_json(site, peer, path, body)
            }
        }
        "/package" | "/package/members" | "/leave" => {
            if media_type(request) != "application/x-www-form-urlencoded" {
                plain(StatusCode::UNSUPPORTED_MEDIA_TYPE, "a form")
            } else if !from_this_page(site, request) {
                plain(StatusCode::FORBIDDEN, "only from this exit's page")
            } else {
                crate::manage::as_form(site, peer, path, body)
            }
        }
        _ => plain(StatusCode::NOT_FOUND, "nothing here"),
    }
}

/// A request's body: at most `most` bytes, within `time`. None for one that
/// is larger or slower.
async fn body_of(body: Incoming, most: usize, time: Duration) -> Option<Bytes> {
    let collected = tokio::time::timeout(time, Limited::new(body, most).collect()).await.ok()?.ok()?;
    Some(collected.to_bytes())
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
                let site = site.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let response = match body_of(body, limits.body_bytes, limits.header_time).await {
                        Some(body) => respond(&site, mesh_peer, &Request::from_parts(parts, ()), &body),
                        None => plain(StatusCode::PAYLOAD_TOO_LARGE, "a body too large, or too slow"),
                    };
                    Ok::<_, Infallible>(response)
                }
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
            npub: "npub1Example".into(),
            address: "fd14::1".parse().unwrap(),
            name: "An exit".into(),
            about: String::new(),
            country: None,
        };
        Arc::new(Site::new(config, exit, Arc::new(Store::in_memory()), Seats::default(), Arc::default()))
    }

    fn get(path: &str, host: &str) -> Request<()> {
        Request::builder().uri(path).header(header::HOST, host).body(()).unwrap()
    }

    #[test]
    fn a_request_names_this_exit_or_is_refused() {
        let site = site();
        let peer = "fd99::2".parse().unwrap();
        for host in ["npub1example.fips:5170", "NPUB1EXAMPLE.FIPS:5170"] {
            assert_eq!(respond(&site, peer, &get("/v1/terms", host), b"").status(), StatusCode::OK, "{host}");
        }
        // Not the bare address either: it is reached only by way of the name.
        for host in [
            "[fd14::1]:5170",
            "[fd14::1]",
            "fd14::1:5170",
            "evil.example",
            "npub1example.fips",
            "npub1example.fips:80",
            "localhost:5170",
            "",
        ] {
            assert_eq!(
                respond(&site, peer, &get("/v1/terms", host), b"").status(),
                StatusCode::MISDIRECTED_REQUEST,
                "{host}"
            );
        }
        let no_host = Request::builder().uri("/v1/terms").body(()).unwrap();
        assert_eq!(respond(&site, peer, &no_host, b"").status(), StatusCode::MISDIRECTED_REQUEST);
    }

    #[test]
    fn what_there_is_and_what_there_is_not() {
        let (site, peer, host) = (site(), "fd99::2".parse().unwrap(), "npub1example.fips:5170");
        let terms = respond(&site, peer, &get("/v1/terms", host), b"");
        assert_eq!(terms.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(terms.headers()[header::CACHE_CONTROL], "no-store");
        let page = respond(&site, peer, &get("/", host), b"");
        assert_eq!(page.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert!(page.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().starts_with("default-src 'none'"));
        assert_eq!(respond(&site, peer, &get("/style.css", host), b"").status(), StatusCode::OK);
        for path in ["/v1/terms/", "/v2/terms", "/index.html", "/../etc/passwd", "/v1/orders"] {
            assert_eq!(respond(&site, peer, &get(path, host), b"").status(), StatusCode::NOT_FOUND, "{path}");
        }
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
            let request =
                Request::builder().method(method.clone()).uri("/v1/terms").header(header::HOST, host).body(()).unwrap();
            let response = respond(&site, peer, &request, b"");
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
            assert_eq!(response.headers()[header::ALLOW], "GET, HEAD");
        }
    }

    fn post(path: &str, kind: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::HOST, "npub1example.fips:5170")
            .header(header::CONTENT_TYPE, kind);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.body(()).unwrap()
    }

    /// What changes something is not to be sent from a page elsewhere: JSON
    /// that no other page may send, or a form from this exit's own page.
    #[test]
    fn a_change_comes_from_here_or_from_a_program() {
        let (site, peer) = (site(), "fd99::2".parse().unwrap());
        let ours = "http://npub1example.fips:5170";
        let json = b"{}";
        let status = |request: Request<()>, body: &[u8]| respond(&site, peer, &request, body).status();
        // JSON: from a program (no origin), or from this page.
        assert_eq!(status(post("/v1/leave", "application/json", &[]), json), StatusCode::OK);
        assert_eq!(
            status(post("/v1/leave", "application/json; charset=utf-8", &[("origin", ours)]), json),
            StatusCode::OK
        );
        assert_eq!(status(post("/v1/leave", "Application/JSON", &[("sec-fetch-site", "none")]), json), StatusCode::OK);
        assert_eq!(status(post("/v1/leave", "text/plain", &[]), json), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            status(post("/v1/leave", "application/x-www-form-urlencoded", &[]), json),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            status(post("/v1/leave", "application/json", &[("origin", "http://evil.example")]), json),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(post("/v1/leave", "application/json", &[("sec-fetch-site", "cross-site")]), json),
            StatusCode::FORBIDDEN
        );
        // A form: from this page, and from nowhere else, nor from nowhere.
        let form = "application/x-www-form-urlencoded";
        assert_eq!(status(post("/leave", form, &[("origin", ours)]), b""), StatusCode::OK);
        assert_eq!(
            status(post("/leave", form, &[("origin", ours), ("sec-fetch-site", "same-origin")]), b""),
            StatusCode::OK
        );
        assert_eq!(status(post("/leave", form, &[]), b""), StatusCode::FORBIDDEN);
        assert_eq!(status(post("/leave", form, &[("origin", "null")]), b""), StatusCode::FORBIDDEN);
        assert_eq!(status(post("/leave", form, &[("origin", "http://evil.example")]), b""), StatusCode::FORBIDDEN);
        assert_eq!(
            status(post("/leave", form, &[("origin", ours), ("sec-fetch-site", "cross-site")]), b""),
            StatusCode::FORBIDDEN
        );
        assert_eq!(status(post("/leave", "text/plain", &[("origin", ours)]), b""), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        // The ways in are POST only; the terms are GET only.
        assert_eq!(status(get("/leave", "npub1example.fips:5170"), b""), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(status(get("/v1/package", "npub1example.fips:5170"), b""), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn a_body_too_large_is_refused() {
        let at = server(Limits::default(), |_| true).await;
        let mut request =
            b"POST /v1/package HTTP/1.1\r\nHost: npub1example.fips:5170\r\nContent-Type: application/json\r\n\
            Content-Length: 20000\r\nConnection: close\r\n\r\n"
                .to_vec();
        request.extend(std::iter::repeat_n(b' ', 20_000));
        let answer = exchange(at, &request).await;
        assert!(answer.starts_with("HTTP/1.1 413"), "{answer:.60}");
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
        let answer =
            exchange(at, b"GET /v1/terms HTTP/1.1\r\nHost: npub1example.fips:5170\r\nConnection: close\r\n\r\n").await;
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        let body = answer.split("\r\n\r\n").nth(1).unwrap();
        let terms: serde_json::Value = serde_json::from_str(body).unwrap();
        // Loopback, as an IPv6 address: in use, the mesh address of the caller.
        assert_eq!(terms["you"]["address"], "::1");
        assert_eq!(terms["price_msat_per_gb"], 2_000_000);
        assert_eq!(terms["methods"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn a_head_is_the_head_of_a_get() {
        let at = server(Limits::default(), |_| true).await;
        let get =
            exchange(at, b"GET /v1/terms HTTP/1.1\r\nHost: npub1example.fips:5170\r\nConnection: close\r\n\r\n").await;
        let head =
            exchange(at, b"HEAD /v1/terms HTTP/1.1\r\nHost: npub1example.fips:5170\r\nConnection: close\r\n\r\n").await;
        let (get_head, get_body) = get.split_once("\r\n\r\n").unwrap();
        let length =
            |text: &str| text.lines().find_map(|line| line.strip_prefix("content-length: ")).map(str::to_string);
        assert_eq!(length(&head.replace("\r\n\r\n", "")), length(get_head), "{head}");
        assert_eq!(length(get_head), Some(get_body.len().to_string()));
        assert!(head.ends_with("\r\n\r\n"), "no body: {head:?}");
    }

    #[tokio::test]
    async fn a_peer_off_the_mesh_gets_nothing() {
        let at = server(Limits::default(), on_the_mesh).await;
        let answer =
            exchange(at, b"GET /v1/terms HTTP/1.1\r\nHost: npub1example.fips:5170\r\nConnection: close\r\n\r\n").await;
        assert_eq!(answer, "", "closed without a word");
    }

    #[tokio::test]
    async fn a_header_too_large_or_too_slow_ends_the_connection() {
        let limits = Limits { header_time: Duration::from_millis(500), ..Limits::default() };
        let at = server(limits, |_| true).await;
        let mut big = b"GET /v1/terms HTTP/1.1\r\nHost: npub1example.fips:5170\r\nX-Filler: ".to_vec();
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
        let third =
            exchange(at, b"GET /v1/terms HTTP/1.1\r\nHost: npub1example.fips:5170\r\nConnection: close\r\n\r\n").await;
        assert_eq!(third, "", "a third from the same address is closed");
        drop(held);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let again =
            exchange(at, b"GET /v1/terms HTTP/1.1\r\nHost: npub1example.fips:5170\r\nConnection: close\r\n\r\n").await;
        assert!(again.starts_with("HTTP/1.1 200"), "places are given back: {again:.40}");
    }
}
