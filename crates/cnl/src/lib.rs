//! Click'n'Load 2 (#37): a link site's button posts its links to a small web server on this
//! computer, as JDownloader's page for web sites documents it
//! (<https://jdownloader.org/knowledge/wiki/glossary/cnl2>, read 2026-11-09):
//!
//! - The server listens on `127.0.0.1:9666`, this computer only.
//! - `GET /jdcheck.js` answers `jdownloader=true;`: the page's script sees a program is there.
//!   `GET /flash/` answers a page with "JDownloader" in it, the documented check by hand.
//! - `POST /flash/addcrypted2` (form): `crypted`, the links (one a line) encrypted with
//!   AES-128-CBC, the key as IV too, in Base64; `jk`, a JavaScript function returning that key in
//!   hexadecimal (only its `return '…'` is read, no script is run); `passwords`, the archive
//!   passwords; `source`, the page; `package`, its name.
//! - `POST /flash/add`: `urls`, the links as they are ("plain CNL2"), with the same fields.
//!
//! Any web page can post to it, so what it takes is limited ([`MAX_BODY`], [`MAX_LINKS`],
//! [`POSTS_PER_MINUTE`]) and only ever shown: the app asks once per site before a package goes to
//! Link grabber, where nothing is looked up or downloaded until the user acts on it. Off unless
//! the user turns it on. (`/flash/addcrypted`, a DLC container, isn't taken: reading one needs a
//! key MDM can't use, #486.)

mod crypto;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};

use crypto::{aes_cbc_decrypt, base64};

/// The documented port.
pub const PORT: u16 = 9666;
/// The most a post may be: a page's few hundred links fit many times over.
pub const MAX_BODY: usize = 256 * 1024;
/// The most links one post may bring; a post with more is refused.
pub const MAX_LINKS: usize = 500;
/// The most passwords kept from a post, and the longest password or package name.
pub const MAX_PASSWORDS: usize = 10;
pub const MAX_TEXT: usize = 200;
/// Posts taken a minute, from all pages together; more are refused until the minute is over.
pub const POSTS_PER_MINUTE: usize = 10;

/// A set of links as a site packed them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Package {
    /// The site's name for it; empty when it gave none.
    pub name: String,
    /// The archive passwords that came with it (Link grabber's "Archive password").
    pub passwords: Vec<String>,
    pub links: Vec<String>,
}

/// What a page posted, and the site it came from: the host of the browser's `Origin` (else its
/// `Referer`, else the form's `source`), None when none says. Only the browser's own headers
/// name the site a page is on; the form's fields are the page's to choose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub package: Package,
    pub site: Option<String>,
}

/// Called for each post taken, off the async threads: whether the app took it.
pub type OnFound = Arc<dyn Fn(Found) -> bool + Send + Sync>;

/// The key in `jk`'s `return '…'` (or `"…"`): 32 hexadecimal digits.
pub fn key_of(jk: &str) -> Option<[u8; 16]> {
    let after = &jk[jk.find("return")? + "return".len()..];
    let after = after.trim_start();
    let quote = after.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let hex = after[1..].split(quote).next()?.trim();
    if hex.len() != 32 {
        return None;
    }
    let mut key = [0u8; 16];
    for (k, pair) in key.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *k = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(key)
}

/// `crypted` opened with `jk`'s key: its links.
pub fn decrypt(crypted: &str, jk: &str) -> Option<Vec<String>> {
    let key = key_of(jk)?;
    let data = base64(crypted)?;
    let plain = aes_cbc_decrypt(&key, &key, &data)?;
    Some(crypto::lines(&String::from_utf8_lossy(&plain)))
}

/// At most `max` characters of `s`, trimmed.
fn short(s: &str, max: usize) -> String {
    s.trim().chars().take(max).collect()
}

/// The passwords a form sent: one a line (or a single one), at most [`MAX_PASSWORDS`].
fn passwords(form: &HashMap<String, String>) -> Vec<String> {
    form.get("passwords")
        .map(|p| {
            p.lines()
                .map(|p| short(p, MAX_TEXT))
                .filter(|p| !p.is_empty())
                .take(MAX_PASSWORDS)
                .collect()
        })
        .unwrap_or_default()
}

fn form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

/// A web address's host, lower case.
fn host(address: &str) -> Option<String> {
    url::Url::parse(address)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
}

/// The site a post came from (see [`Found`]).
fn site(headers: &HeaderMap, form: &HashMap<String, String>) -> Option<String> {
    let header = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(host)
    };
    header(header::ORIGIN)
        .or_else(|| header(header::REFERER))
        .or_else(|| form.get("source").and_then(|s| host(s)))
}

/// What a post is: its package, or why not (the answer's text).
fn read(path: &str, form: &HashMap<String, String>) -> Result<Package, &'static str> {
    let links = match path {
        "addcrypted2" => {
            let (Some(c), Some(jk)) = (form.get("crypted"), form.get("jk")) else {
                return Err("failed: crypted and jk are needed");
            };
            decrypt(c, jk).ok_or("failed: the links can't be read")?
        }
        "add" => crypto::lines(form.get("urls").map_or("", |u| u)),
        _ => return Err("failed: unknown"),
    };
    if links.is_empty() {
        return Err("failed: no links");
    }
    if links.len() > MAX_LINKS {
        return Err("failed: too many links");
    }
    Ok(Package {
        name: form
            .get("package")
            .map(|n| short(n, MAX_TEXT))
            .unwrap_or_default(),
        passwords: passwords(form),
        links,
    })
}

/// The posts of the last minute, to keep them under [`POSTS_PER_MINUTE`].
#[derive(Default)]
struct Rate(Mutex<VecDeque<Instant>>);

impl Rate {
    /// One more post now, if the minute has room.
    fn take(&self, now: Instant) -> bool {
        let mut sent = self.0.lock().unwrap();
        while sent
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            sent.pop_front();
        }
        if sent.len() >= POSTS_PER_MINUTE {
            return false;
        }
        sent.push_back(now);
        true
    }
}

/// The server, while kept: dropping it stops listening.
pub struct Listener {
    task: tokio::task::JoinHandle<()>,
    pub addr: SocketAddr,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Listener {
    /// Listen on `addr` (`127.0.0.1:9666`; tests: port 0) on `rt`. An error when it can't, such
    /// as the port being taken (JDownloader running): nothing listens then.
    pub fn start(
        rt: &tokio::runtime::Handle,
        addr: SocketAddr,
        on_found: OnFound,
    ) -> std::io::Result<Listener> {
        let std = std::net::TcpListener::bind(addr)?;
        std.set_nonblocking(true)?;
        let addr = std.local_addr()?;
        let _in = rt.enter();
        let listener = tokio::net::TcpListener::from_std(std)?;
        let app = router(on_found);
        let task = rt.spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::warn!("Click'n'Load stopped: {e}");
            }
        });
        tracing::info!("Click'n'Load listening on {addr}");
        Ok(Listener { task, addr })
    }
}

fn router(on_found: OnFound) -> Router {
    let rate = Arc::new(Rate::default());
    let posted = move |path: &'static str| {
        let (on_found, rate) = (on_found.clone(), rate.clone());
        move |headers: HeaderMap, body: Bytes| {
            let (on_found, rate) = (on_found.clone(), rate.clone());
            async move {
                let form = form(&body);
                let package = match read(path, &form) {
                    Ok(p) => p,
                    Err(why) => return text(why),
                };
                if !rate.take(Instant::now()) {
                    tracing::info!("Click'n'Load: a post refused, too many this minute");
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        text("failed: too many, try again in a minute"),
                    )
                        .into_response();
                }
                let found = Found {
                    package,
                    site: site(&headers, &form),
                };
                let took = tokio::task::spawn_blocking(move || on_found(found))
                    .await
                    .unwrap_or(false);
                text(if took { "success" } else { "failed: not taken" })
            }
        }
    };
    Router::new()
        .route("/jdcheck.js", get(jdcheck))
        .route("/flash", get(flash))
        .route("/flash/", get(flash))
        .route("/flash/add", post(posted("add")))
        .route("/flash/addcrypted2", post(posted("addcrypted2")))
        .fallback(any(other))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::map_response(open_to_pages))
}

fn text(s: &str) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{s}\r\n"),
    )
        .into_response()
}

async fn jdcheck() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript")],
        "jdownloader=true;\n",
    )
        .into_response()
}

async fn flash() -> Response {
    text("JDownloader (Click'n'Load by Mister Download Manager)")
}

/// A browser's preflight (CORS, Private Network Access) is allowed; anything else isn't here.
async fn other(method: Method) -> Response {
    if method == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Pages from anywhere may post here (that is the point): the browser is told so, Chrome's
/// "private network" check included. What they post is limited, asked for per site, and only
/// ever shown, never looked up or started by itself.
async fn open_to_pages(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    h.insert(
        "access-control-allow-private-network",
        HeaderValue::from_static("true"),
    );
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documentation's own example: key "1234567890987654", two links.
    const DOC_JK: &str = "function f(){ return '31323334353637383930393837363534';}";

    fn doc_crypted() -> String {
        use base64::Engine;
        let links = "http://rapidshare.com/files/285626259/jDownloader.dmg\r\n\
                     http://rapidshare.com/files/285622259/jDownloader2.dmg";
        let key = *b"1234567890987654";
        base64::engine::general_purpose::STANDARD.encode(crate::crypto::aes_cbc_encrypt(
            &key,
            &key,
            links.as_bytes(),
        ))
    }

    #[test]
    fn the_documented_example_opens() {
        assert_eq!(key_of(DOC_JK), Some(*b"1234567890987654"));
        assert_eq!(
            key_of(r#"function f(){return "31323334353637383930393837363534"}"#),
            Some(*b"1234567890987654")
        );
        assert_eq!(key_of("function f(){ return x(); }"), None);
        // The page's example value, as published.
        assert_eq!(
            decrypt(
                "DRurBGEf2ntP7Z0WDkMP8e1ZeK7PswJGeBHCg4zEYXZSE3Qqxsbi5EF1KosgkKQ9SL8qOOUAI+eDPFypAtQS9A==",
                DOC_JK
            ),
            Some(vec![
                "http://rapidshare.com/files/285626259/jDownloader.dmg".to_owned()
            ])
        );
        assert_eq!(
            decrypt(&doc_crypted(), DOC_JK).unwrap(),
            vec![
                "http://rapidshare.com/files/285626259/jDownloader.dmg",
                "http://rapidshare.com/files/285622259/jDownloader2.dmg"
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_page_posts_its_links_to_the_listener() {
        let got: Arc<Mutex<Vec<Found>>> = Arc::default();
        let seen = got.clone();
        let l = Listener::start(
            &tokio::runtime::Handle::current(),
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(move |f| {
                seen.lock().unwrap().push(f);
                true
            }),
        )
        .unwrap();
        let base = format!("http://{}", l.addr);
        let c = reqwest::Client::new();
        let check = c.get(format!("{base}/jdcheck.js")).send().await.unwrap();
        assert_eq!(
            check
                .headers()
                .get("access-control-allow-private-network")
                .unwrap(),
            "true"
        );
        assert_eq!(check.text().await.unwrap(), "jdownloader=true;\n");
        let post = |path: &str, form: Vec<(&str, String)>| {
            let req = c.post(format!("{base}/flash/{path}")).body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(form)
                    .finish(),
            );
            async move {
                req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            post(
                "addcrypted2",
                vec![
                    ("package", "  Holiday  ".into()),
                    ("crypted", doc_crypted()),
                    ("jk", DOC_JK.into()),
                    ("passwords", "myPassword".into()),
                    ("source", "http://jdownloader.org/spielwiese".into()),
                ]
            )
            .await,
            "success\r\n"
        );
        assert_eq!(
            post(
                "add",
                vec![(
                    "urls",
                    "https://a.example/1.zip\nhttps://a.example/2.zip".into()
                )]
            )
            .await,
            "success\r\n"
        );
        assert_eq!(
            post("addcrypted2", vec![("crypted", "AAAA".into())]).await,
            "failed: crypted and jk are needed\r\n"
        );
        let got = got.lock().unwrap().clone();
        assert_eq!(
            got[0],
            Found {
                package: Package {
                    name: "Holiday".into(),
                    passwords: vec!["myPassword".into()],
                    links: vec![
                        "http://rapidshare.com/files/285626259/jDownloader.dmg".into(),
                        "http://rapidshare.com/files/285622259/jDownloader2.dmg".into(),
                    ],
                },
                // No browser headers here: the form's source names the site.
                site: Some("jdownloader.org".into()),
            }
        );
        assert_eq!(got.len(), 2);
        // A DLC container isn't taken (#486).
        assert_eq!(post("addcrypted", vec![("crypted", "x".into())]).await, "");
        drop(l);
    }

    #[test]
    fn a_taken_port_says_so() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let first = Listener::start(
            rt.handle(),
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(|_| true),
        )
        .unwrap();
        assert!(Listener::start(rt.handle(), first.addr, Arc::new(|_| true)).is_err());
    }

    #[test]
    fn the_browsers_origin_names_the_site_not_the_form() {
        let mut h = HeaderMap::new();
        let f: HashMap<String, String> =
            [("source".to_owned(), "https://claimed.example/p".to_owned())].into();
        assert_eq!(site(&h, &f).as_deref(), Some("claimed.example"));
        h.insert(
            header::REFERER,
            "https://Page.Example/list".parse().unwrap(),
        );
        assert_eq!(site(&h, &f).as_deref(), Some("page.example"));
        h.insert(header::ORIGIN, "https://links.example".parse().unwrap());
        assert_eq!(site(&h, &f).as_deref(), Some("links.example"));
        // A sandboxed page's "null" origin names none: the next one says.
        h.insert(header::ORIGIN, "null".parse().unwrap());
        assert_eq!(site(&h, &f).as_deref(), Some("page.example"));
    }

    #[test]
    fn posts_are_capped() {
        let many: String = (0..=MAX_LINKS)
            .map(|i| format!("https://a.example/{i}\n"))
            .collect();
        let f = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert_eq!(
            read("add", &f(&[("urls", &many)])),
            Err("failed: too many links")
        );
        let pws: String = (0..20).map(|i| format!("pw{i}\n")).collect();
        let long = "n".repeat(1000);
        let p = read(
            "add",
            &f(&[
                ("urls", "https://a.example/1"),
                ("passwords", &pws),
                ("package", &long),
            ]),
        )
        .unwrap();
        assert_eq!(p.passwords.len(), MAX_PASSWORDS);
        assert_eq!(p.name.chars().count(), MAX_TEXT);
        assert_eq!(read("addcrypted", &f(&[])), Err("failed: unknown"));
    }

    #[test]
    fn ten_posts_a_minute() {
        let rate = Rate::default();
        let t = Instant::now();
        for _ in 0..POSTS_PER_MINUTE {
            assert!(rate.take(t));
        }
        assert!(!rate.take(t + Duration::from_secs(30)));
        assert!(rate.take(t + Duration::from_secs(61)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_flood_is_refused_and_a_big_post_too() {
        let n = Arc::new(Mutex::new(0usize));
        let seen = n.clone();
        let l = Listener::start(
            &tokio::runtime::Handle::current(),
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(move |_| {
                *seen.lock().unwrap() += 1;
                true
            }),
        )
        .unwrap();
        let c = reqwest::Client::new();
        let url = format!("http://{}/flash/add", l.addr);
        let send = |body: String| {
            c.post(&url)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, "https://flood.example")
                .body(body)
                .send()
        };
        let mut refused = 0;
        for i in 0..POSTS_PER_MINUTE + 5 {
            let r = send(format!("urls=https%3A%2F%2Fa.example%2F{i}"))
                .await
                .unwrap();
            if r.status() == StatusCode::TOO_MANY_REQUESTS {
                refused += 1;
            }
        }
        assert_eq!((*n.lock().unwrap(), refused), (POSTS_PER_MINUTE, 5));
        let big = format!("urls={}", "a".repeat(MAX_BODY + 1));
        assert_eq!(
            send(big).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
