//! Click'n'Load 2: a link site's button posts its links to a small web server on this computer,
//! as JDownloader's page for web sites documents it
//! (<https://jdownloader.org/knowledge/wiki/glossary/cnl2>, read 2026-11-09):
//!
//! - The server listens on `127.0.0.1:9666`, this computer only.
//! - `GET /jdcheck.js` answers `jdownloader=true;`: the page's script sees a program is there.
//!   `GET /flash/` answers a page with "JDownloader" in it, the documented check by hand.
//! - `POST /flash/addcrypted2` (form): `crypted`, the links (one a line) encrypted with
//!   AES-128-CBC, the key as IV too, in Base64; `jk`, a JavaScript function returning that key in
//!   hexadecimal (only its `return '…'` is read, no script is run); `passwords`, the archive
//!   passwords; `source`, the page.
//! - `POST /flash/add`: `urls`, the links as they are ("plain CNL2"), with `passwords` and
//!   `source`. `POST /flash/addcrypted`: `crypted`, a DLC container.
//!
//! Any web page can post to it, so nothing it sends is downloaded by itself: the app shows the
//! links in Link grabber to tick first. Off unless the user turns it on.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};

use crate::{Package, aes_cbc_decrypt, base64};

/// The documented port.
pub const PORT: u16 = 9666;

/// What a page posted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    /// Its links, and the page it came from.
    Links {
        package: Package,
        source: Option<String>,
    },
    /// A DLC container's text (`/flash/addcrypted`): the app reads it as a `.dlc` file.
    Dlc {
        text: String,
        source: Option<String>,
    },
}

/// Called for each post, off the async threads: whether the app took it.
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
    Some(crate::lines(&String::from_utf8_lossy(&plain)))
}

/// The passwords a form sent: one a line (or a single one).
fn passwords(form: &HashMap<String, String>) -> Vec<String> {
    form.get("passwords")
        .map(|p| {
            p.lines()
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

/// The page it came from, when it is a web address.
fn source(form: &HashMap<String, String>) -> Option<String> {
    form.get("source")
        .filter(|s| url::Url::parse(s).is_ok_and(|u| matches!(u.scheme(), "http" | "https")))
        .cloned()
}

/// What a post is: the links found, or why not (the answer's text).
fn read(path: &str, form: &HashMap<String, String>) -> Result<Found, &'static str> {
    let package = |links: Vec<String>| {
        if links.is_empty() {
            return Err("failed: no links");
        }
        Ok(Found::Links {
            package: Package {
                name: form.get("package").cloned().unwrap_or_default(),
                passwords: passwords(form),
                links,
            },
            source: source(form),
        })
    };
    match path {
        "addcrypted2" => {
            let (Some(c), Some(jk)) = (form.get("crypted"), form.get("jk")) else {
                return Err("failed: crypted and jk are needed");
            };
            package(decrypt(c, jk).ok_or("failed: the links can't be read")?)
        }
        "add" => package(crate::lines(form.get("urls").map_or("", |u| u))),
        "addcrypted" => match form.get("crypted") {
            Some(t) if crate::dlc::looks_like(t) => Ok(Found::Dlc {
                text: t.clone(),
                source: source(form),
            }),
            _ => Err("failed: not a DLC container"),
        },
        _ => Err("failed: unknown"),
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
    let posted = move |path: &'static str| {
        let on_found = on_found.clone();
        move |body: Bytes| {
            let on_found = on_found.clone();
            async move {
                let found = match read(path, &form(&body)) {
                    Ok(f) => f,
                    Err(why) => return text(why),
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
        .route("/flash/addcrypted", post(posted("addcrypted")))
        .route("/flash/addcrypted2", post(posted("addcrypted2")))
        .fallback(any(other))
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
/// "private network" check included. What they post is only ever shown, never started.
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
    use std::sync::Mutex;

    /// The documentation's own example: key "1234567890987654", two links.
    const DOC_JK: &str = "function f(){ return '31323334353637383930393837363534';}";

    fn doc_crypted() -> String {
        use base64::Engine;
        let links = "http://rapidshare.com/files/285626259/jDownloader.dmg\r\n\
                     http://rapidshare.com/files/285622259/jDownloader2.dmg";
        let key = *b"1234567890987654";
        base64::engine::general_purpose::STANDARD.encode(crate::aes_cbc_encrypt(
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
            Found::Links {
                package: Package {
                    name: String::new(),
                    passwords: vec!["myPassword".into()],
                    links: vec![
                        "http://rapidshare.com/files/285626259/jDownloader.dmg".into(),
                        "http://rapidshare.com/files/285622259/jDownloader2.dmg".into(),
                    ],
                },
                source: Some("http://jdownloader.org/spielwiese".into()),
            }
        );
        assert_eq!(got.len(), 2);
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
}
