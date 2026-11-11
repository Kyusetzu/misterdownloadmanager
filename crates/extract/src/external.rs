//! 7z and RAR through 7-Zip, run as its own program (#37): UnRAR's licence forbids using its
//! code in a GPL program, so MDM never links it, and 7z's decoder isn't built in either (it cost
//! about 1 MB). 7-Zip writes into the staging folder; what it wrote is
//! then checked as our own entries are ([`safe::check_tree`]) before anything is moved into
//! place.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::Error;
use crate::safe::{self, Writer};

/// 7-Zip's program: in its usual install folders on Windows, else `7zz`, `7z` or `7za` on the
/// PATH (Linux and macOS packages name it so).
pub fn find_7zip() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
            if let Some(dir) = std::env::var_os(var) {
                candidates.push(PathBuf::from(dir).join("7-Zip").join("7z.exe"));
            }
        }
    }
    let names: &[&str] = if cfg!(windows) {
        &["7z.exe", "7za.exe"]
    } else {
        &["7zz", "7z", "7za"]
    };
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for n in names {
                candidates.push(dir.join(n));
            }
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

pub fn extract(
    tool: &Path,
    archive: &Path,
    w: &mut Writer,
    password: Option<&str>,
) -> Result<(), Error> {
    let mut cmd = Command::new(tool);
    cmd.arg("x").arg("-y").arg("-bso0").arg("-bsp0");
    // A password goes in on 7-Zip's standard input, where it asks for one when the archive is
    // encrypted, never on its command line, which other programs can read. Without one, an
    // empty `-p`: 7-Zip then fails at once on an encrypted archive instead of waiting for an
    // answer.
    if password.is_none() {
        cmd.arg("-p");
    }
    cmd.arg(format!("-o{}", w.root().display()))
        .arg("--")
        .arg(archive)
        .stdin(if password.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // No console window flashing up for it.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    // The password is never logged.
    tracing::info!("extract: {} x {}", tool.display(), archive.display());
    let mut child = cmd.spawn()?;
    if let (Some(pw), Some(mut input)) = (password, child.stdin.take()) {
        // One line, then the end (dropped): asked again, 7-Zip finds nothing and stops. Not
        // asked (the archive isn't encrypted), it never reads it.
        let _ = writeln!(input, "{pw}");
    }
    let out = child.wait_with_output()?;
    let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
    if !out.status.success() {
        return Err(
            if err.contains("wrong password") || err.contains("encrypted") {
                if password.is_some() {
                    Error::WrongPassword
                } else {
                    Error::NeedsPassword
                }
            } else if err.contains("missing volume") || err.contains("unexpected end of archive") {
                Error::MissingVolume(0)
            } else {
                Error::Damaged(
                    err.lines()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("7-Zip failed")
                        .trim()
                        .to_owned(),
                )
            },
        );
    }
    for (name, why) in safe::check_tree(w.root(), 64)? {
        w.skip(&name, why);
    }
    Ok(())
}
