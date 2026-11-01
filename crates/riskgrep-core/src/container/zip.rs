//! Zip archives, and the formats built on them (jar, docx, xlsx, wheels).
//! Every use of the `zip` crate's API is in this module.

use super::{ContainerError, Extractor, Flow, MemberMeta, NotRead, Walk};
use crate::classify::{Budgeted, Source};
use std::cell::Cell;
use std::io::BufReader;

/// Bytes the central directory may take to find and parse (the end record
/// is searched for backwards from the end of the file).
const DIRECTORY_MAX: u64 = 8_388_608;

pub struct Zip;

pub static ZIP: Zip = Zip;

impl Extractor for Zip {
    fn id(&self) -> &'static str {
        "zip"
    }

    fn version(&self) -> u32 {
        1
    }

    fn extract(
        &self,
        src: &dyn Source,
        size: u64,
        walk: &mut dyn Walk,
    ) -> Result<(), ContainerError> {
        let left = Cell::new(DIRECTORY_MAX);
        let over = Cell::new(false);
        let reader = BufReader::with_capacity(
            8192,
            Budgeted {
                src,
                size,
                pos: 0,
                left: &left,
                over: &over,
            },
        );
        let mut zip = match zip::ZipArchive::new(reader) {
            Ok(z) if !over.get() => z,
            _ if over.get() => {
                return Err(ContainerError(format!(
                    "zip central directory not read within {DIRECTORY_MAX} bytes"
                )))
            }
            _ => return Err(ContainerError("zip central directory unreadable".into())),
        };
        // Member data is bounded by the walk (bytes produced, ratio,
        // deadline), not by this reader.
        left.set(u64::MAX);
        let is_dir = |zip: &zip::ZipArchive<_>, i: usize| {
            zip.name_for_index(i).is_some_and(|n| n.ends_with('/'))
        };
        let n = zip.len();
        for i in 0..n {
            if is_dir(&zip, i) {
                continue;
            }
            let name = zip.name_for_index(i).unwrap_or_default().to_string();
            let (meta, encrypted) = match zip.by_index_raw(i) {
                Ok(f) => (
                    MemberMeta {
                        name,
                        declared_size: Some(f.size()),
                        compressed_size: Some(f.compressed_size()),
                    },
                    f.encrypted(),
                ),
                Err(_) => (
                    MemberMeta {
                        name,
                        declared_size: None,
                        compressed_size: None,
                    },
                    false,
                ),
            };
            let flow = if encrypted {
                walk.not_read(meta, NotRead::Encrypted)
            } else {
                match zip.by_index(i) {
                    Ok(mut f) => walk.member(meta, &mut f),
                    Err(zip::result::ZipError::UnsupportedArchive(m))
                        if m == zip::result::ZipError::PASSWORD_REQUIRED =>
                    {
                        walk.not_read(meta, NotRead::Encrypted)
                    }
                    Err(zip::result::ZipError::UnsupportedArchive(_)) => {
                        walk.not_read(meta, NotRead::Unsupported)
                    }
                    Err(_) => walk.not_read(meta, NotRead::Corrupt),
                }
            };
            if flow == Flow::Stop {
                let rest = (i + 1..n).filter(|&j| !is_dir(&zip, j)).count();
                walk.rest(rest as u64);
                break;
            }
        }
        Ok(())
    }
}
