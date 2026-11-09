//! Safe archive extraction (#37): zip (Deflate, Deflate64, AES), tar and its gz/xz forms and a
//! single `.gz`/`.xz` file in process; 7z (split `.7z.001` too) and RAR through an installed
//! 7-Zip, run as its own program (UnRAR's licence forbids linking it into a GPL program, and a 7z
//! decoder in MDM cost about 1 MB for a format most people who use it have 7-Zip for).
//!
//! Every archive is extracted into an empty staging folder beside the destination, each entry's
//! path checked ([`safe`]), then moved into place: a folder named after the archive when it holds
//! several things at its top (or always / never, as asked), a file that exists already kept and
//! the new one numbered. One path for every format and for the external tool, and a failure
//! leaves nothing behind but the archive.
//!
//! Portable, no unsafe, no UI and no words: errors are an enum the app words.

mod external;
pub mod hatchzip;
pub mod safe;
mod single;
mod tar_fmt;
pub mod volumes;
mod zip_fmt;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

pub use external::find_7zip;
pub use hatchzip::find_hatchzip;
pub use safe::Limits;
pub use volumes::{Volume, VolumeKind, volume_key};

/// What an archive is, by its first bytes (and, for a compressed tar, its name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Zip,
    SevenZip,
    Rar,
    Tar,
    TarGz,
    TarXz,
    /// One file compressed with gzip (not a tar).
    Gz,
    /// One file compressed with xz (not a tar).
    Xz,
}

impl Format {
    /// The format of the archive at `path` (its first volume for a split one), or None when it
    /// isn't one MDM extracts.
    pub fn detect(path: &Path) -> std::io::Result<Option<Format>> {
        use std::io::Read;
        let mut head = [0u8; 512];
        let mut f = std::fs::File::open(path)?;
        let mut n = 0;
        while n < head.len() {
            let got = f.read(&mut head[n..])?;
            if got == 0 {
                break;
            }
            n += got;
        }
        let head = &head[..n];
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        Ok(Self::from_head(head, &name))
    }

    fn from_head(head: &[u8], name: &str) -> Option<Format> {
        let tar_named = |exts: &[&str]| exts.iter().any(|e| name.ends_with(e));
        if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
            Some(Format::Zip)
        } else if head.starts_with(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) {
            Some(Format::SevenZip)
        } else if head.starts_with(b"Rar!\x1A\x07") {
            Some(Format::Rar)
        } else if head.starts_with(&[0x1F, 0x8B]) {
            Some(if tar_named(&[".tar.gz", ".tgz"]) {
                Format::TarGz
            } else {
                Format::Gz
            })
        } else if head.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
            Some(if tar_named(&[".tar.xz", ".txz"]) {
                Format::TarXz
            } else {
                Format::Xz
            })
        } else if head.len() >= 262 && &head[257..262] == b"ustar" {
            Some(Format::Tar)
        } else {
            None
        }
    }
}

/// Where the archive's contents go: straight into the destination, or a folder named after it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Subfolder {
    /// A folder named after the archive when it holds more than one thing at its top (KDE Ark,
    /// 7-Zip's "smart"): one folder or one file goes straight into the destination.
    #[default]
    Smart,
    Always,
    Never,
}

/// How to extract one archive.
pub struct Policy<'a> {
    /// The folder the contents go into (usually the archive's own).
    pub dest: PathBuf,
    pub subfolder: Subfolder,
    pub password: Option<String>,
    pub limits: Limits,
    /// 7-Zip's program, for 7z and RAR ([`find_7zip`] finds it). None: not installed, and those
    /// archives fail with [`Error::NoTool`].
    pub tool: Option<PathBuf>,
    /// HatchZip's program ([`find_hatchzip`]), optional: 7z and RAR go to it when 7-Zip isn't
    /// installed, and every archive it reads when `in_place` is set.
    pub hatchzip: Option<PathBuf>,
    /// Extract in place with HatchZip (when it is installed): the archive is removed while its
    /// files come out, so only they need room. Without HatchZip, a normal extraction.
    pub in_place: bool,
    /// Told every file put in place: the app marks it as downloaded from the internet, as the
    /// archive is.
    pub on_file: &'a mut dyn FnMut(&Path),
    /// Set from elsewhere to stop (the download was deleted, MDM is closing).
    pub cancel: Option<&'a AtomicBool>,
}

/// What an extraction did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Where the contents went (the destination, or the folder made for them).
    pub folder: PathBuf,
    pub files: u64,
    pub bytes: u64,
    /// Entries left out, with why ("link", "goes outside the folder"…).
    pub skipped: Vec<(String, &'static str)>,
    /// Files put in place under another name, one of that name being there already.
    pub renamed: u64,
    /// Extracted in place by HatchZip: the archive (every volume) is gone.
    pub in_place: bool,
}

/// Why an archive wasn't extracted.
#[derive(Debug)]
pub enum Error {
    /// It's encrypted and no password was given.
    NeedsPassword,
    WrongPassword,
    /// Volume `n` of a split archive isn't there (1-based; 0 when the tool didn't say which).
    MissingVolume(u32),
    /// Damaged or not what its name says; the decoder's words, for the log.
    Damaged(String),
    /// It would write more than the limit (a bomb, or not enough free space).
    TooBig {
        would: u64,
        limit: u64,
    },
    /// More entries or deeper folders than allowed.
    TooMany,
    /// 7z or RAR, and no 7-Zip was found.
    NoTool,
    /// Not enough free space, HatchZip says (its words); nothing was changed.
    NoRoom(String),
    /// An extraction in place stopped partway: what came out is in this folder, the rest is
    /// still in the archive. Extracting again continues.
    Partial(PathBuf),
    /// Not an archive MDM extracts.
    Unsupported,
    Cancelled,
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NeedsPassword => write!(f, "needs a password"),
            Error::WrongPassword => write!(f, "wrong password"),
            Error::MissingVolume(0) => write!(f, "a volume is missing"),
            Error::MissingVolume(n) => write!(f, "volume {n} is missing"),
            Error::Damaged(s) => write!(f, "damaged: {s}"),
            Error::TooBig { would, limit } => {
                write!(f, "would write {would} bytes (limit {limit})")
            }
            Error::TooMany => write!(f, "too many entries or folders too deep"),
            Error::NoTool => write!(f, "7z and RAR archives need 7-Zip, and none was found"),
            Error::NoRoom(s) => write!(f, "not enough free space: {s}"),
            Error::Partial(dir) => {
                write!(f, "stopped partway; extracted so far: {}", dir.display())
            }
            Error::Unsupported => write!(f, "not an archive MDM extracts"),
            Error::Cancelled => write!(f, "cancelled"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// The archive's name without its archive extensions (`movie.part1.rar` → `movie`,
/// `photos.tar.gz` → `photos`, `x.7z.001` → `x`): the folder [`Subfolder`] makes.
pub fn base_name(archive: &Path) -> String {
    let name = archive
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(v) = volume_key(&name) {
        return v.base;
    }
    let lower = name.to_lowercase();
    for ext in [
        ".tar.gz", ".tar.xz", ".tgz", ".txz", ".zip", ".7z", ".rar", ".tar", ".gz", ".xz",
    ] {
        if lower.ends_with(ext) && lower.len() > ext.len() {
            return name[..name.len() - ext.len()].to_owned();
        }
    }
    name
}

/// Extract `archive` (a split archive's first volume) as `policy` says.
pub fn extract(archive: &Path, policy: &mut Policy<'_>) -> Result<Report, Error> {
    let format = Format::detect(archive)?.ok_or(Error::Unsupported)?;
    // In place: every archive HatchZip reads (a single .gz or .xz file isn't one to it). An
    // extraction in place that stopped partway is always finished by HatchZip: part of the
    // archive is already gone, and only it knows where it was.
    if (policy.in_place || hatchzip::unfinished(archive))
        && let Some(tool) = policy.hatchzip.clone()
        && !matches!(format, Format::Gz | Format::Xz)
    {
        return in_place(&tool, archive, policy);
    }
    let staging = safe::Staging::new(&policy.dest)?;
    let mut w = safe::Writer::new(staging.path(), policy.limits, policy.cancel);
    let run = match format {
        Format::Zip => zip_fmt::extract(archive, &mut w, policy.password.as_deref()),
        Format::Tar | Format::TarGz | Format::TarXz => tar_fmt::extract(archive, format, &mut w),
        Format::Gz | Format::Xz => single::extract(archive, format, &mut w),
        Format::SevenZip | Format::Rar => {
            // A split 7z's volumes are all there before 7-Zip is asked (it would only say
            // "unexpected end"): the first one missing is named.
            let name = archive
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if volume_key(&name).is_some_and(|v| v.kind == VolumeKind::Split) {
                volumes::MultiFile::open(archive)?.map_err(Error::MissingVolume)?;
            }
            let password = policy.password.as_deref();
            match (&policy.tool, &policy.hatchzip) {
                (Some(tool), _) => external::extract(tool, archive, &mut w, password),
                // No 7-Zip: HatchZip, leaving the archive as it is.
                (None, Some(hz)) => {
                    let root = w.root().to_path_buf();
                    let skipped =
                        hatchzip::extract(hz, archive, &root, password, true, policy.cancel)?;
                    for (name, why) in skipped {
                        w.skip(&name, why);
                    }
                    Ok(())
                }
                (None, None) => Err(Error::NoTool),
            }
        }
    };
    run?;
    let skipped = w.take_skipped();
    let (mut report, placed) =
        staging.place(&base_name(archive), policy.subfolder, policy.on_file)?;
    report.skipped = skipped;
    report.files = placed;
    report.bytes = w.bytes();
    Ok(report)
}

/// HatchZip extracts `archive` in place into its own folder beside it ([`hatchzip::work_folder`]),
/// then what came out is put where `policy` says, as our own extractions are. A failure leaves
/// that folder alone once something is in it: those files are no longer in the archive.
fn in_place(tool: &Path, archive: &Path, policy: &mut Policy<'_>) -> Result<Report, Error> {
    let name = archive
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if volume_key(&name).is_some_and(|v| v.kind == VolumeKind::Split) {
        volumes::MultiFile::open(archive)?.map_err(Error::MissingVolume)?;
    }
    let base = base_name(archive);
    let out = hatchzip::work_folder(&policy.dest, &base);
    let run = hatchzip::extract(
        tool,
        archive,
        &out,
        policy.password.as_deref(),
        false,
        policy.cancel,
    );
    let skipped = match run {
        Ok(s) => s,
        Err(e) => {
            let started = std::fs::read_dir(&out).is_ok_and(|mut d| d.next().is_some());
            // A wrong password or too little room changes nothing, HatchZip promises.
            let untouched = matches!(
                e,
                Error::NeedsPassword | Error::WrongPassword | Error::NoRoom(_)
            );
            if started && !untouched {
                return Err(Error::Partial(out));
            }
            // Removed only when empty: never anything it wrote.
            let _ = std::fs::remove_dir(&out);
            return Err(e);
        }
    };
    let (mut report, placed) =
        safe::Staging::adopt(&policy.dest, out).place(&base, policy.subfolder, policy.on_file)?;
    report.skipped = skipped;
    report.files = placed;
    report.in_place = true;
    Ok(report)
}

#[cfg(test)]
mod tests;
