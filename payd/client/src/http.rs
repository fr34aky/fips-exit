//! The little of HTTP this program speaks: one request on a connection of
//! its own, answered with JSON, over the mesh.
//!
//! There is no TLS here and none is missing: fips has encrypted the
//! connection end to end, and the address connected to is the exit's key
//! ([`crate::reach`]). What comes back is still an exit's word, and an
//! exit is not trusted with this terminal or this node's memory: an answer
//! is so long at the most, takes so long at the most, and is JSON or it is
//! nothing.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The most an answer may be, head and body: the service's longest is a
/// package with its members, a few kilobytes.
const MOST: usize = 256 * 1024;
/// How long connecting may take. The first packet to a node the mesh has no
/// way to yet takes a while.
const CONNECT: Duration = Duration::from_secs(15);

/// Where the exit's payment service is.
#[derive(Debug, Clone, PartialEq)]
pub struct Exit {
    pub npub: String,
    /// What it is asked as: `<npub>.fips:<port>`. The service answers to
    /// no other name.
    pub host: String,
    pub at: SocketAddr,
}

/// What the service answered.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub status: u16,
    pub body: Value,
}

/// Why there is no answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Failed {
    /// Nothing was sent: the service was not reached.
    NotReached(String),
    /// The request was sent, or may have been, and what became of it is
    /// not known.
    NotKnown(String),
    /// Refused, and not in an exit's words: the service turns away what
    /// it does not read (too long, to another name than its own) with a
    /// line of text. Sent again, it is refused again.
    Refused(String),
}

impl Failed {
    pub fn said(&self) -> &str {
        match self {
            Failed::NotReached(why) | Failed::NotKnown(why) | Failed::Refused(why) => why,
        }
    }
}

/// Ask the exit: `method` `path`, with `body` as JSON if there is one. The
/// whole of it within `patience`.
pub fn ask(exit: &Exit, method: &str, path: &str, body: Option<&Value>, patience: Duration) -> Result<Answer, Failed> {
    let until = Instant::now() + patience;
    let mut stream = TcpStream::connect_timeout(&exit.at, CONNECT.min(patience))
        .map_err(|e| Failed::NotReached(format!("no connection to {} at {}: {e}", exit.host, exit.at)))?;
    let body = body.map(Value::to_string);
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nUser-Agent: fips-exit-pay\r\n\
         Connection: close\r\n",
        exit.host
    );
    if let Some(body) = &body {
        request.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    request.push_str(body.as_deref().unwrap_or_default());
    let lost = |what: &str, e: std::io::Error| Failed::NotKnown(format!("{what} {}: {e}", exit.host));
    stream.set_write_timeout(Some(left(until))).map_err(|e| lost("sending to", e))?;
    stream.write_all(request.as_bytes()).map_err(|e| lost("sending to", e))?;
    let mut answer = Vec::new();
    let mut some = [0u8; 8192];
    loop {
        stream.set_read_timeout(Some(left(until))).map_err(|e| lost("reading from", e))?;
        match stream.read(&mut some) {
            Ok(0) => break,
            Ok(n) => answer.extend_from_slice(&some[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(lost("no answer in time from", e)),
        }
        if answer.len() > MOST {
            return Err(Failed::NotKnown(format!("{} answered with more than this program reads", exit.host)));
        }
        if Instant::now() >= until {
            return Err(Failed::NotKnown(format!("no answer in time from {}", exit.host)));
        }
    }
    read(&answer).map_err(|(status, why)| match status {
        Some(status) if (400..500).contains(&status) => Failed::Refused(format!(
            "{} refused, with {status} and not in an exit's words: is this its payment service, asked at its own port?",
            exit.host
        )),
        _ => Failed::NotKnown(format!("{} answered with {why}", exit.host)),
    })
}

/// What is left until `until`, and never nothing: a timeout of zero is no
/// timeout to a socket.
fn left(until: Instant) -> Duration {
    until.saturating_duration_since(Instant::now()).max(Duration::from_millis(1))
}

/// An answer as it came: a status, and a body that is one JSON object. Or
/// why it is none; with its status where it has one and is not JSON.
fn read(answer: &[u8]) -> Result<Answer, (Option<u16>, String)> {
    let no = |why: &str| (None, why.to_string());
    let split = answer.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| no("what is no HTTP answer"))?;
    let head = std::str::from_utf8(&answer[..split]).map_err(|_| no("what is no HTTP answer"))?;
    let body = &answer[split + 4..];
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 ").or_else(|| line.strip_prefix("HTTP/1.0 ")))
        .and_then(|rest| rest.get(..3))
        .and_then(|digits| digits.parse::<u16>().ok())
        .filter(|status| (200..600).contains(status))
        .ok_or_else(|| no("what is no HTTP answer"))?;
    let (mut json, mut length) = (false, None);
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| no("what is no HTTP answer"))?;
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-type" => json = value.to_ascii_lowercase().starts_with("application/json"),
            "content-length" => length = Some(value.parse::<usize>().map_err(|_| no("a length that is none"))?),
            // The service sends a body whole, with its length.
            "transfer-encoding" => return Err(no("a body in pieces, which this program does not read")),
            _ => {}
        }
    }
    if length.is_some_and(|length| length != body.len()) {
        return Err(no("less than it said it would"));
    }
    if !json {
        return Err((Some(status), format!("{status}, and not with JSON: is this an exit's payment service?")));
    }
    let body: Value = serde_json::from_slice(body).map_err(|_| no("what is not JSON"))?;
    if !body.is_object() {
        return Err(no("JSON that is no object"));
    }
    Ok(Answer { status, body })
}

/// A stand-in for an exit's service, for the tests here and of the
/// commands.
#[cfg(test)]
pub mod testing {
    use super::*;
    use std::net::TcpListener;

    /// A service that answers each connection with the next of `answers`,
    /// whatever is asked, and says what it was asked.
    pub fn service(answers: Vec<Vec<u8>>) -> (Exit, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let exit = Exit { npub: "npub1x".into(), host: "npub1x.fips:5170".into(), at: listener.local_addr().unwrap() };
        let served = std::thread::spawn(move || {
            let mut asked = Vec::new();
            for answer in answers {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut some = [0u8; 4096];
                // Up to the end of the head, and the body it announces.
                loop {
                    let n = stream.read(&mut some).unwrap();
                    request.extend_from_slice(&some[..n]);
                    let text = String::from_utf8_lossy(&request).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("Content-Length: "))
                            .map_or(0, |n| n.parse::<usize>().unwrap());
                        if body.len() >= length {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                asked.push(String::from_utf8_lossy(&request).to_string());
                let _ = stream.write_all(&answer);
            }
            asked
        });
        (exit, served)
    }

    pub fn json(status: &str, body: &str) -> Vec<u8> {
        format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}", body.len())
            .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{json, service};
    use super::*;
    use std::net::TcpListener;

    const SOON: Duration = Duration::from_secs(5);

    #[test]
    fn a_request_is_asked_as_the_service_wants_it_and_its_answer_read() {
        let (exit, served) =
            service(vec![json("200 OK", "{\"version\":1}"), json("409 Conflict", "{\"code\":\"used\"}")]);
        let terms = ask(&exit, "GET", "/v1/terms", None, SOON).unwrap();
        assert_eq!((terms.status, &terms.body["version"]), (200, &1.into()));
        let order = serde_json::json!({ "package": "1gb", "token": "cashuB" });
        let refused = ask(&exit, "POST", "/v1/orders", Some(&order), SOON).unwrap();
        assert_eq!((refused.status, &refused.body["code"]), (409, &"used".into()));
        let asked = served.join().unwrap();
        assert!(asked[0].starts_with("GET /v1/terms HTTP/1.1\r\nHost: npub1x.fips:5170\r\n"), "{}", asked[0]);
        assert!(!asked[0].contains("Content-Type") && !asked[0].to_ascii_lowercase().contains("origin"));
        assert!(asked[1].starts_with("POST /v1/orders HTTP/1.1\r\nHost: npub1x.fips:5170\r\n"), "{}", asked[1]);
        assert!(asked[1].contains("Content-Type: application/json\r\n") && asked[1].ends_with(&order.to_string()));
    }

    #[test]
    fn what_is_no_answer_of_the_service_is_not_taken_for_one() {
        let long = format!("{{\"a\":\"{}\"}}", "x".repeat(MOST));
        let answers = vec![
            b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n<h1>hello</h1>".to_vec(),
            json("200 OK", "[1, 2]"),
            json("200 OK", "{\"cut\": "),
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 40\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
                .to_vec(),
            b"SSH-2.0-OpenSSH_9.9\r\n".to_vec(),
            json("200 OK", &long),
            b"HTTP/1.1 999 What\r\ncontent-type: application/json\r\n\r\n{}".to_vec(),
        ];
        let (exit, served) = service(answers.clone());
        for _ in &answers {
            let failed = ask(&exit, "GET", "/v1/terms", None, SOON).unwrap_err();
            assert!(matches!(failed, Failed::NotKnown(_)), "{failed:?}");
            assert!(!failed.said().contains('\u{1b}') && failed.said().len() < 300, "{failed:?}");
        }
        served.join().unwrap();
    }

    #[test]
    fn a_refusal_in_a_line_of_text_is_a_refusal_and_not_something_unknown() {
        let text = |status: &str| format!("HTTP/1.1 {status}\r\ncontent-type: text/plain\r\n\r\nno\n").into_bytes();
        let (exit, served) = service(vec![
            text("413 Payload Too Large"),
            text("421 Misdirected Request"),
            text("500 Internal Server Error"),
        ]);
        for refused in [true, true, false] {
            let failed = ask(&exit, "GET", "/v1/terms", None, SOON).unwrap_err();
            assert_eq!(matches!(failed, Failed::Refused(_)), refused, "{failed:?}");
        }
        served.join().unwrap();
    }

    #[test]
    fn a_service_that_is_not_there_or_says_nothing_is_not_waited_for() {
        // Nobody listens there.
        let gone = TcpListener::bind("[::1]:0").unwrap();
        let exit = Exit { npub: "npub1x".into(), host: "npub1x.fips:5170".into(), at: gone.local_addr().unwrap() };
        drop(gone);
        assert!(matches!(ask(&exit, "GET", "/v1/terms", None, SOON), Err(Failed::NotReached(_))));
        // Somebody listens, and never answers.
        let silent = TcpListener::bind("[::1]:0").unwrap();
        let exit = Exit { at: silent.local_addr().unwrap(), ..exit };
        let began = Instant::now();
        let failed = ask(&exit, "GET", "/v1/terms", None, Duration::from_millis(400)).unwrap_err();
        assert!(matches!(failed, Failed::NotKnown(_)), "{failed:?}");
        assert!(began.elapsed() < Duration::from_secs(3));
    }
}
