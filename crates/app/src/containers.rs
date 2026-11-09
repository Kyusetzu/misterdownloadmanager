//! Link containers and Click'n'Load in the app (`mdm_containers`): a `.dlc` file opened,
//! dropped or imported, and the links a page's Click'n'Load button posts while Options →
//! Archives and Link grabber → "Accept Click'n'Load from web pages" is on. Both end in Link
//! grabber, one package each as the site packed them, with its archive password: nothing is
//! downloaded before it is ticked there.
//!
//! The work runs off the window's thread (a DLC asks JDownloader's key service); what arrives is
//! kept in an inbox the window empties each frame (`App::poll_containers`).

use std::sync::{Arc, Mutex};

use mdm_containers::{Package, cnl, dlc};

use crate::transfer::Imported;

/// What arrived for Link grabber, or why a container couldn't be read.
pub enum Arrived {
    /// The links, and where they came from as Link grabber says it (a file's name, "Click'n'Load").
    Links {
        found: Vec<Imported>,
        source: String,
    },
    /// A container that couldn't be read: its name and why, in the interface language.
    Failed { file: String, why: String },
}

/// Click'n'Load's listener, while on, and the inbox.
pub struct Containers {
    rt: tokio::runtime::Handle,
    ctx: egui::Context,
    inbox: Arc<Mutex<Vec<Arrived>>>,
    listener: Option<cnl::Listener>,
}

impl Containers {
    pub fn new(rt: tokio::runtime::Handle, ctx: egui::Context) -> Self {
        Containers {
            rt,
            ctx,
            inbox: Arc::default(),
            listener: None,
        }
    }

    /// Listen for Click'n'Load (`on`) or stop. Starting can fail, the port being taken (by
    /// JDownloader, most often): why, in the interface language.
    pub fn listen(&mut self, on: bool) -> Result<(), String> {
        if !on {
            self.listener = None;
            return Ok(());
        }
        if self.listener.is_some() {
            return Ok(());
        }
        let (inbox, ctx, rt) = (self.inbox.clone(), self.ctx.clone(), self.rt.clone());
        let on_found: cnl::OnFound = Arc::new(move |found| {
            match found {
                cnl::Found::Links { package, source } => {
                    put(
                        &inbox,
                        &ctx,
                        links(vec![package], source.as_deref(), "Click'n'Load"),
                    );
                }
                cnl::Found::Dlc { text, source } => {
                    read_dlc(&rt, &inbox, &ctx, text, "Click'n'Load".into(), source);
                }
            }
            true
        });
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], cnl::PORT));
        match cnl::Listener::start(&self.rt, addr, on_found) {
            Ok(l) => {
                self.listener = Some(l);
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Click'n'Load can't listen on {addr}: {e}");
                Err(if e.kind() == std::io::ErrorKind::AddrInUse {
                    crate::i18n::fmt(
                        // i18n: notice: Click'n'Load couldn't start; {port} is 9666; JDownloader is another download manager that uses the same port
                        crate::i18n::t(
                            "Click'n'Load can't start: another program (JDownloader?) is using port {port}. Close it, then turn Click'n'Load off and on again in Options.",
                        ),
                        &[("port", &cnl::PORT.to_string())],
                    )
                } else {
                    crate::i18n::fmt(
                        // i18n: notice: Click'n'Load couldn't start; {error} the system's reason
                        crate::i18n::t("Click'n'Load can't start: {error}"),
                        &[("error", &e.to_string())],
                    )
                })
            }
        }
    }

    /// Read a `.dlc` file's text (named `file`, for what Link grabber and errors say).
    pub fn open_dlc(&self, text: String, file: String) {
        read_dlc(&self.rt, &self.inbox, &self.ctx, text, file, None);
    }

    /// What arrived since the last frame.
    pub fn take(&self) -> Vec<Arrived> {
        std::mem::take(&mut *self.inbox.lock().unwrap())
    }
}

/// Is `path` a DLC container (by its name)?
pub fn is_dlc(path: &str) -> bool {
    path.trim_matches('"')
        .to_ascii_lowercase()
        .ends_with(".dlc")
}

fn put(inbox: &Mutex<Vec<Arrived>>, ctx: &egui::Context, a: Arrived) {
    inbox.lock().unwrap().push(a);
    ctx.request_repaint();
}

/// Link grabber's rows for `packages`: each link with its package's name (the site's, else
/// `fallback`) and its first archive password; the page it came from as their referrer.
fn links(packages: Vec<Package>, page: Option<&str>, fallback: &str) -> Arrived {
    let found = packages
        .into_iter()
        .flat_map(|p| {
            let name = if p.name.trim().is_empty() {
                fallback.to_owned()
            } else {
                p.name.trim().to_owned()
            };
            let password = p.passwords.first().cloned();
            p.links.into_iter().map(move |url| Imported {
                url,
                referer: page.map(str::to_owned),
                package: Some(name.clone()),
                password: password.clone(),
                ..Default::default()
            })
        })
        .collect();
    Arrived::Links {
        found,
        source: fallback.to_owned(),
    }
}

/// Ask the key service for `text`'s key on a thread of its own, through MDM's own network
/// settings (proxy, DNS, adapter), and put the packages (or why not) in the inbox.
fn read_dlc(
    rt: &tokio::runtime::Handle,
    inbox: &Arc<Mutex<Vec<Arrived>>>,
    ctx: &egui::Context,
    text: String,
    file: String,
    page: Option<String>,
) {
    let (inbox, ctx) = (inbox.clone(), ctx.clone());
    rt.spawn(async move {
        let service = url::Url::parse(&service()).expect("an address");
        let read = match mdm_engine::http_client(&crate::settings::own_net(), &service) {
            Ok(client) => dlc::read(&client, &service, &text).await,
            Err(e) => Err(mdm_containers::Error::Service(e.to_string())),
        };
        let arrived = match read {
            Ok(packages) => links(packages, page.as_deref(), &file),
            Err(e) => Arrived::Failed { file, why: why(&e) },
        };
        put(&inbox, &ctx, arrived);
    });
}

/// The key service's address. Debug builds only: MDM_DLC_SERVICE points at a test server.
fn service() -> String {
    #[cfg(debug_assertions)]
    if let Ok(s) = std::env::var("MDM_DLC_SERVICE") {
        return s;
    }
    dlc::SERVICE.to_owned()
}

/// Why a container couldn't be read, in the interface language.
fn why(e: &mdm_containers::Error) -> String {
    match e {
        mdm_containers::Error::Damaged => {
            // i18n: a DLC container couldn't be read: not one, or damaged
            crate::i18n::t("it isn't a DLC container, or it is damaged").to_owned()
        }
        mdm_containers::Error::Empty => {
            // i18n: a DLC container held no links
            crate::i18n::t("it holds no links").to_owned()
        }
        mdm_containers::Error::Service(why) => crate::i18n::fmt(
            // i18n: a DLC container's key couldn't be had from JDownloader's key service; {error} why (in English, from the service or the network)
            crate::i18n::t("JDownloader's key service didn't give its key ({error})"),
            &[("error", why)],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_keep_their_names_and_first_password() {
        let Arrived::Links { found, source } = links(
            vec![
                Package {
                    name: "Holiday".into(),
                    passwords: vec!["one".into(), "two".into()],
                    links: vec!["https://a.example/1.rar".into()],
                },
                Package {
                    name: " ".into(),
                    passwords: vec![],
                    links: vec!["https://b.example/2.zip".into()],
                },
            ],
            Some("https://site.example/page"),
            "list.dlc",
        ) else {
            panic!("links")
        };
        assert_eq!(source, "list.dlc");
        assert_eq!(found[0].package.as_deref(), Some("Holiday"));
        assert_eq!(found[0].password.as_deref(), Some("one"));
        assert_eq!(
            found[0].referer.as_deref(),
            Some("https://site.example/page")
        );
        assert_eq!(found[1].package.as_deref(), Some("list.dlc"));
        assert_eq!(found[1].password, None);
        assert!(is_dlc("C:\\x\\Links.DLC") && is_dlc("\"/tmp/a.dlc\"") && !is_dlc("a.dlc.txt"));
    }
}
