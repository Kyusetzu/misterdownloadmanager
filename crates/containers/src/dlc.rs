//! DLC containers (`.dlc`), the link files JDownloader made and many link sites still offer.
//!
//! **Where this comes from, plainly.** DLC has no public specification: JDownloader's makers
//! keep its keys on their own web service and publish no key for other programs. What this
//! module knows, and how it was learned:
//!
//! - The file's layout, by looking at real containers (2026-11-09): Base64 text, its last 88
//!   characters the container's encrypted key, the rest the encrypted links (a multiple of 16
//!   bytes: a block cipher).
//! - The key service and its answer, by asking it (black box): `GET service.php?srcType=dlc&
//!   destType=<program>&data=<those 88 characters>` answers `<rc>Base64</rc>`, the container's
//!   key encrypted for that program; a key it doesn't know gets HTTP 500.
//! - The one thing that can't be learned from outside: the program key that opens `rc`. MDM uses
//!   the `destType` and AES key that pyLoad (a free download manager, GPL) publishes in its
//!   source, because no other key is public. The service is asked under pyLoad's name for that
//!   reason; MDM still says who it is in its User-Agent. If JDownloader's makers give MDM a key
//!   of its own, it replaces these three constants and nothing else.
//! - The rest follows from that: `rc` decrypted with the program key (AES-128-CBC) is the
//!   container's key, which (as key and IV) decrypts the links into Base64 of an XML document:
//!   `<dlc><header>…</header><content><package name=…><file><url>…`, every value Base64. Real
//!   containers pad that text with zero bytes, then a PKCS#7 block (seen 2026-11-09).
//!
//! The service sees only the container's key part, never its links; it is asked over HTTPS.

use crate::{Error, Package, aes_cbc_decrypt, base64};

/// JDownloader's key service.
pub const SERVICE: &str = "https://service.jdownloader.org/dlcrypt/service.php";

/// The program the service encrypts the key for, and that program's key: pyLoad's, from its
/// published source (see the module's notes).
const DEST_TYPE: &str = "pylo";
const PROGRAM_KEY: [u8; 16] = *b"cb99b5cbc24db398";
const PROGRAM_IV: [u8; 16] = *b"9bc24cb995cb8db3";

/// The length of the key part at the end of a container.
const KEY_PART: usize = 88;

/// Does `text` look like a DLC container (Base64 only, longer than its key part)?
pub fn looks_like(text: &str) -> bool {
    let t = text.trim();
    t.len() > KEY_PART
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\r' | b'\n'))
}

/// The encrypted links and the key part.
fn split(text: &str) -> Result<(Vec<u8>, String), Error> {
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !looks_like(&t) {
        return Err(Error::Damaged);
    }
    let (data, key) = t.split_at(t.len() - KEY_PART);
    let data = base64(data).ok_or(Error::Damaged)?;
    Ok((data, key.to_owned()))
}

/// Read a container: its key from `service` (through `client`, the user's proxy and network
/// settings), then its packages.
pub async fn read(
    client: &reqwest::Client,
    service: &url::Url,
    text: &str,
) -> Result<Vec<Package>, Error> {
    let (data, key) = split(text)?;
    let mut url = service.clone();
    url.query_pairs_mut()
        .append_pair("srcType", "dlc")
        .append_pair("destType", DEST_TYPE)
        .append_pair("data", &key);
    let resp = client
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            concat!("MisterDownloadManager/", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await
        .map_err(|e| Error::Service(without_url(e)))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| Error::Service(without_url(e)))?;
    if status.as_u16() == 500 {
        // What it answers a key it doesn't know.
        return Err(Error::Service("it doesn't know this container".into()));
    }
    if !status.is_success() {
        return Err(Error::Service(format!("HTTP {}", status.as_u16())));
    }
    let rc = body
        .split_once("<rc>")
        .and_then(|(_, r)| r.split_once("</rc>"))
        .map(|(r, _)| r.trim())
        .filter(|r| !r.is_empty())
        .ok_or_else(|| Error::Service("an answer without a key".into()))?;
    open(rc, &data)
}

/// The error without its address (which holds the container's key part).
fn without_url(e: reqwest::Error) -> String {
    e.without_url().to_string()
}

/// With the service's `rc`: the packages.
pub(crate) fn open(rc: &str, data: &[u8]) -> Result<Vec<Package>, Error> {
    let rc = base64(rc).ok_or(Error::Damaged)?;
    let wrapped: [u8; 16] = rc
        .get(..16)
        .and_then(|r| r.try_into().ok())
        .ok_or(Error::Damaged)?;
    let key: [u8; 16] = aes_cbc_decrypt(&PROGRAM_KEY, &PROGRAM_IV, &wrapped)
        .and_then(|k| k.try_into().ok())
        .ok_or(Error::Damaged)?;
    let mut inner = aes_cbc_decrypt(&key, &key, data).ok_or(Error::Damaged)?;
    unpad(&mut inner);
    let inner = String::from_utf8_lossy(&inner);
    let xml = base64(inner.trim_end_matches('\0')).ok_or(Error::Damaged)?;
    packages(&String::from_utf8_lossy(&xml))
}

/// Without a PKCS#7 padding block, when the text ends with one (the zeros before it go with
/// the text's own trimming).
fn unpad(text: &mut Vec<u8>) {
    if let Some(&n) = text.last()
        && (1..=16).contains(&n)
        && text.len() >= n as usize
        && text[text.len() - n as usize..].iter().all(|b| *b == n)
    {
        text.truncate(text.len() - n as usize);
    }
}

/// `<content><package name passwords><file><url>`, every value Base64.
fn packages(xml: &str) -> Result<Vec<Package>, Error> {
    let doc = roxmltree::Document::parse(xml).map_err(|_| Error::Damaged)?;
    let text = |s: &str| {
        base64(s)
            .map(|b| String::from_utf8_lossy(&b).trim().to_owned())
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    for p in doc.descendants().filter(|n| n.has_tag_name("package")) {
        let links: Vec<String> = p
            .descendants()
            .filter(|n| n.has_tag_name("url"))
            .filter_map(|n| n.text())
            .flat_map(|u| crate::lines(&text(u)))
            .collect();
        if links.is_empty() {
            continue;
        }
        out.push(Package {
            name: p.attribute("name").map(text).unwrap_or_default(),
            passwords: passwords(&p.attribute("passwords").map(text).unwrap_or_default()),
            links,
        });
    }
    if out.is_empty() {
        return Err(Error::Empty);
    }
    Ok(out)
}

/// `{}`, `{"one","two"}` or a bare `one`: the passwords.
fn passwords(s: &str) -> Vec<String> {
    s.trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(',')
        .map(|p| p.trim().trim_matches('"').trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes_cbc_encrypt;
    use base64::Engine;

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    /// A container as the tests make it, padded as real ones are (zeros, then a PKCS#7 block):
    /// its links sealed with `key`, and the `rc` the service would answer for it.
    pub(crate) fn sealed(xml: &str, key: &[u8; 16]) -> (String, String) {
        let mut text = b64(xml.as_bytes()).into_bytes();
        text.resize(text.len().div_ceil(16) * 16, 0);
        text.extend([16u8; 16]);
        let data = aes_cbc_encrypt(key, key, &text);
        let key_part = b64(&[7u8; 64]);
        assert_eq!(key_part.len(), KEY_PART);
        let rc = b64(&aes_cbc_encrypt(&PROGRAM_KEY, &PROGRAM_IV, key));
        (format!("{}{key_part}", b64(&data)), rc)
    }

    fn xml() -> String {
        let e = |s: &str| b64(s.as_bytes());
        format!(
            "<dlc><header><generator><app>{}</app></generator></header><content>\
             <package name=\"{}\" passwords=\"{}\" comment=\"{}\">\
             <file><url>{}</url><filename>{}</filename><size>{}</size></file>\
             <file><url>{}</url></file></package>\
             <package name=\"{}\" passwords=\"{}\"><file><url>{}</url></file></package>\
             </content></dlc>",
            e("lab"),
            e("Holiday Videos"),
            e(r#"{"secret","second"}"#),
            e("no comment"),
            e("https://hoster.example/file/1/holiday.part1.rar"),
            e("holiday.part1.rar"),
            e("1906315407"),
            e("https://hoster.example/file/2/holiday.part2.rar"),
            e("Notes"),
            e("{}"),
            e("https://other.example/notes.txt"),
        )
    }

    #[test]
    fn a_container_opens_into_its_packages() {
        let (text, rc) = sealed(&xml(), b"0011223344556677");
        assert!(looks_like(&text));
        let (data, key) = split(&text).unwrap();
        assert_eq!(key.len(), KEY_PART);
        let p = open(&rc, &data).unwrap();
        assert_eq!(
            p,
            vec![
                Package {
                    name: "Holiday Videos".into(),
                    passwords: vec!["secret".into(), "second".into()],
                    links: vec![
                        "https://hoster.example/file/1/holiday.part1.rar".into(),
                        "https://hoster.example/file/2/holiday.part2.rar".into(),
                    ],
                },
                Package {
                    name: "Notes".into(),
                    passwords: vec![],
                    links: vec!["https://other.example/notes.txt".into()],
                },
            ]
        );
    }

    #[test]
    fn damaged_and_empty_containers_say_so() {
        assert!(!looks_like("short"));
        assert!(!looks_like(&format!("{}<html>", "A".repeat(100))));
        assert_eq!(split("not a container"), Err(Error::Damaged));
        let (text, _) = sealed(&xml(), b"0011223344556677");
        let (data, _) = split(&text).unwrap();
        // The service's key for another container: nothing readable comes out.
        let (_, wrong) = sealed(&xml(), b"7766554433221100");
        assert!(open(&wrong, &data).is_err());
        let (text, rc) = sealed("<dlc><content></content></dlc>", b"0011223344556677");
        let (data, _) = split(&text).unwrap();
        assert_eq!(open(&rc, &data), Err(Error::Empty));
        assert_eq!(passwords(" {} "), Vec::<String>::new());
        assert_eq!(passwords("plain"), vec!["plain"]);
    }
}
