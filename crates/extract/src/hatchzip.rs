//! HatchZip (hatchzip.dev, MIT or Apache-2.0), run as its own program like 7-Zip: an optional
//! second extractor. It reads ZIP, 7z, RAR and tar, and can extract *in place*: it cuts each
//! finished part off the archive as it goes, so a large download needs free space for its files
//! only, not for the archive and its files at once.
//!
//! Only its documented command line is used (`hatchzip extract <archive> -o <folder> -y -q`,
//! `--keep-archive`, the `HATCHZIP_PASSWORD` variable and the exit status of its README):
//! 0 done, 1 failed (progress saved), 3 not enough free space (nothing changed), 4 damaged
//! (nothing deleted), 5 password missing or wrong, 130 paused.
//!
//! In place, what is already extracted is no longer in the archive. So it is never extracted
//! into a staging folder that a failure would remove: it goes into a folder of its own beside the
//! archive ([`work_folder`]), which stays when HatchZip stops partway. Running it again with the
//! same folder continues where it stopped (HatchZip keeps its progress next to the archive).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::Error;
use crate::safe;

/// HatchZip's command line program on the PATH (its installers and packages put `hatchzip`
/// there; the desktop app alone, `hatchzip-gui`, isn't enough).
pub fn find_hatchzip() -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "hatchzip.exe"
    } else {
        "hatchzip"
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// The folder an extraction in place goes into before it is put where the settings say:
/// `<archive's name>.hatchzip-out` beside the archive. The same every time for one archive, so a
/// second run continues the first.
pub fn work_folder(dest: &Path, base: &str) -> PathBuf {
    let name = mdm_engine::naming::sanitize(base);
    let name = if name.is_empty() {
        "extracted".to_owned()
    } else {
        name
    };
    dest.join(format!("{name}.hatchzip-out"))
}

/// Whether HatchZip has an unfinished extraction of `archive` (its progress file beside it).
pub fn unfinished(archive: &Path) -> bool {
    let mut p = archive.as_os_str().to_owned();
    p.push(".hatchzip");
    Path::new(&p).exists()
}

/// Extract `archive` into `out` (made if missing). `keep`: leave the archive as it is (a normal
/// extraction); otherwise in place. The password goes through the environment, never the
/// command line (which other programs can read). `cancel` stops it: HatchZip is safe to stop
/// at any moment. Returns what was left out of what it wrote (links, unsafe names).
pub fn extract(
    tool: &Path,
    archive: &Path,
    out: &Path,
    password: Option<&str>,
    keep: bool,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<(String, &'static str)>, Error> {
    std::fs::create_dir_all(out)?;
    let mut cmd = Command::new(tool);
    cmd.arg("extract")
        .arg(archive)
        .arg("-o")
        .arg(out)
        .args(["-y", "-q"]);
    if keep {
        cmd.arg("--keep-archive");
    }
    cmd.env_remove("HATCHZIP_PASSWORD");
    if let Some(pw) = password {
        cmd.env("HATCHZIP_PASSWORD", pw);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    // The password is never logged.
    tracing::info!(
        "extract: {} extract {}{}",
        tool.display(),
        archive.display(),
        if keep {
            " --keep-archive"
        } else {
            " (in place)"
        }
    );
    let mut child = cmd.spawn()?;
    // stderr is read on its own thread so a long message can't fill the pipe and stall it.
    let mut pipe = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(p) = pipe.as_mut() {
            let _ = std::io::Read::read_to_string(p, &mut s);
        }
        s
    });
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let err = reader.join().unwrap_or_default();
    let Some(status) = status else {
        return Err(Error::Cancelled);
    };
    let first = || {
        err.lines()
            .map(|l| l.trim().trim_start_matches("error:").trim())
            .find(|l| !l.is_empty())
            .unwrap_or("HatchZip failed")
            .to_owned()
    };
    match status.code() {
        Some(0) => {}
        Some(5) => {
            return Err(if password.is_some() {
                Error::WrongPassword
            } else {
                Error::NeedsPassword
            });
        }
        Some(3) => return Err(Error::NoRoom(first())),
        Some(130) => return Err(Error::Cancelled),
        _ => return Err(Error::Damaged(first())),
    }
    // What it wrote is checked as our own entries are (no links leading out, no deep trees).
    Ok(safe::check_tree(out, 64)?)
}
