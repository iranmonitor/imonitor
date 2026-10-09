use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 16 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECTION_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

struct ActiveConnectionGuard(Arc<AtomicUsize>);

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub raw_path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub form: BTreeMap<String, String>,
}

impl Request {
    pub fn cookie(&self, key: &str) -> Option<&str> {
        self.cookies.get(key).map(String::as_str)
    }

    pub fn form_value(&self, key: &str) -> &str {
        self.form.get(key).map(String::as_str).unwrap_or("")
    }

    pub fn query_value(&self, key: &str) -> &str {
        self.query.get(key).map(String::as_str).unwrap_or("")
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn html(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8".to_string(),
            headers: Vec::new(),
            body: body.into_bytes(),
        }
    }

    pub fn text(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8".to_string(),
            headers: Vec::new(),
            body: body.into_bytes(),
        }
    }

    pub fn json(status: u16, value: &Value) -> Self {
        let body = serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec());
        Self {
            status,
            content_type: "application/json; charset=utf-8".to_string(),
            headers: Vec::new(),
            body,
        }
    }

    pub fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            content_type: "text/plain; charset=utf-8".to_string(),
            headers: vec![("Location".to_string(), location.to_string())],
            body: format!("Redirecting to {location}").into_bytes(),
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }
}

pub fn serve(
    listen_addr: &str,
    handler: Arc<dyn Fn(Request) -> Response + Send + Sync + 'static>,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen_addr)
        .map_err(|error| format!("failed to bind {listen_addr}: {error}"))?;
    let active_connections = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let previous = active_connections.fetch_add(1, Ordering::AcqRel);
                if previous >= MAX_CONCURRENT_CONNECTIONS {
                    active_connections.fetch_sub(1, Ordering::AcqRel);
                    let _ = write_response(
                        &mut stream,
                        Response::text(503, "server is busy; retry shortly".to_string()),
                    );
                    continue;
                }
                let handler = Arc::clone(&handler);
                let connection_count = Arc::clone(&active_connections);
                thread::spawn(move || {
                    let _active_guard = ActiveConnectionGuard(connection_count);
                    if let Err(error) = handle_connection(stream, &handler) {
                        eprintln!("http connection error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("http accept error: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    handler: &Arc<dyn Fn(Request) -> Response + Send + Sync + 'static>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(CONNECTION_READ_TIMEOUT))
        .map_err(|error| format!("failed to set connection read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(CONNECTION_WRITE_TIMEOUT))
        .map_err(|error| format!("failed to set connection write timeout: {error}"))?;
    let request = parse_request(&mut stream)?;
    let response = handler(request);
    write_response(&mut stream, response)
}

fn parse_request(stream: &mut TcpStream) -> Result<Request, String> {
    let mut reader = BufReader::new(stream);
    let request_line = read_limited_line(&mut reader, MAX_REQUEST_LINE_BYTES, "request line")?;
    if request_line.trim().is_empty() {
        return Err("received empty request line".to_string());
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let raw_path = parts.next().unwrap_or("/").to_string();

    let mut headers = BTreeMap::new();
    let mut total_header_bytes = 0_usize;
    loop {
        let line = read_limited_line(&mut reader, MAX_HEADER_LINE_BYTES, "request header")?;
        total_header_bytes = total_header_bytes.saturating_add(line.len());
        if total_header_bytes > MAX_HEADER_BYTES {
            return Err("request headers exceeded the 64 KiB limit".to_string());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_string(), value.trim().to_string());
        }
    }

    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| {
            value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length header".to_string())
        })
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err("request body exceeded the 8 MiB limit".to_string());
    }

    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|error| format!("failed to read request body: {error}"))?;
    }

    let (path, query) = split_query(&raw_path);
    let cookies = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        .map(|(_, value)| parse_cookie_header(value))
        .unwrap_or_default();

    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default();
    let form = if content_type.starts_with("application/x-www-form-urlencoded") {
        let text = String::from_utf8_lossy(&body);
        parse_www_form_urlencoded(&text)
    } else {
        BTreeMap::new()
    };

    Ok(Request {
        method,
        path,
        raw_path,
        query,
        headers,
        cookies,
        body,
        form,
    })
}

fn read_limited_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
    description: &str,
) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(limit.min(1024));
    let read = reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|error| format!("failed to read {description}: {error}"))?;
    if read > limit {
        return Err(format!("{description} exceeded the {limit}-byte limit"));
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn split_query(raw_path: &str) -> (String, BTreeMap<String, String>) {
    if let Some((path, query)) = raw_path.split_once('?') {
        (path.to_string(), parse_www_form_urlencoded(query))
    } else {
        (raw_path.to_string(), BTreeMap::new())
    }
}

fn parse_cookie_header(value: &str) -> BTreeMap<String, String> {
    let mut cookies = BTreeMap::new();
    for part in value.split(';') {
        if let Some((name, cookie_value)) = part.trim().split_once('=') {
            cookies.insert(name.trim().to_string(), url_decode(cookie_value.trim()));
        }
    }
    cookies
}

pub fn parse_www_form_urlencoded(input: &str) -> BTreeMap<String, String> {
    let mut output = BTreeMap::new();
    for pair in input.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        output.insert(url_decode(name), url_decode(value));
    }
    output
}

pub fn url_decode(input: &str) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.as_bytes().iter().copied();
    while let Some(byte) = chars.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hi = chars.next().unwrap_or(b'0');
                let lo = chars.next().unwrap_or(b'0');
                let value = decode_hex(hi) * 16 + decode_hex(lo);
                bytes.push(value);
            }
            _ => bytes.push(byte),
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

fn decode_hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

pub fn url_encode(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => output.push(byte as char),
            b' ' => output.push('+'),
            _ => output.push_str(&format!("%{:02X}", byte)),
        }
    }
    output
}

fn write_response(stream: &mut TcpStream, response: Response) -> Result<(), String> {
    let status_text = match response.status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    };

    let mut headers = vec![
        ("Content-Type".to_string(), response.content_type),
        ("Content-Length".to_string(), response.body.len().to_string()),
        ("Connection".to_string(), "close".to_string()),
        ("Cache-Control".to_string(), "no-store".to_string()),
    ];
    headers.extend(response.headers);

    let mut wire = format!("HTTP/1.1 {} {}\r\n", response.status, status_text);
    for (key, value) in headers {
        wire.push_str(&format!("{key}: {value}\r\n"));
    }
    wire.push_str("\r\n");
    stream
        .write_all(wire.as_bytes())
        .map_err(|error| format!("failed to write response headers: {error}"))?;
    stream
        .write_all(&response.body)
        .map_err(|error| format!("failed to write response body: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("failed to flush response: {error}"))
}
