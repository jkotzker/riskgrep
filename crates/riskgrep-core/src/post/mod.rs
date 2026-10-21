//! Post-processors: Rust refinements applied to each YARA match.

mod entropy;
mod floats;
mod span;
mod tensor;
mod words;

use crate::meta::PostSpec;
use crate::model::ShapeFacts;
use regex::bytes::{Regex, RegexBuilder};
use std::collections::BTreeMap;
use std::ops::Range;

pub use entropy::Entropy;
pub use floats::{float_arrays, FloatArray, FloatRun};
pub use span::{AllowRegex, Span};
pub use tensor::{NpyHeader, NpzMembers, SafetensorsHeader};
pub(crate) use tensor::{NPZ_MAX_MEMBERS, NPZ_MEMBER_BYTES};
pub use words::Stopwords;

#[derive(Debug, Clone, PartialEq)]
pub enum PostResult {
    Keep(Range<usize>),
    /// Several ranges, each continuing through the rest of the chain on its
    /// own (one per secret found in the match).
    KeepAll(Vec<Range<usize>>),
    KeepWithShape(Range<usize>, ShapeFacts),
    Drop,
}

pub trait Post: Send + Sync {
    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult;

    /// True when the verdict depends only on `content`, never on the match
    /// range, so the engine may compute it once per rule per scan.
    fn whole_content(&self) -> bool {
        false
    }

    /// Processors that find their own ranges return them here, computed in
    /// one pass over `content`; the engine then uses them instead of the
    /// rule's pattern matches (which only trigger the rule). `Some(vec![])`
    /// means the rule yields no evidence.
    fn runs(&self, _content: &[u8]) -> Option<Vec<Range<usize>>> {
        None
    }

    /// True for processors that can turn one match into several ranges
    /// ([`PostResult::KeepAll`]). The engine then runs them on every
    /// distinct match rather than only on the outermost ones, so no secret
    /// is lost to a match that contains another.
    fn splits(&self) -> bool {
        false
    }

    /// For a splitting processor that is first in its chain: the ranges it
    /// yields over all of `windows`, merged, computed without repeating
    /// work that overlapping windows share. `None` to apply it per window.
    fn apply_windows(
        &self,
        _content: &[u8],
        _windows: &[Range<usize>],
    ) -> Option<Vec<Range<usize>>> {
        None
    }
}

/// Compile a regex with the bundle-wide settings.
pub fn compile_regex(src: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(src)
        .unicode(false)
        .size_limit(1 << 28)
        .build()
}

/// Build the processor for one spec, compiling its regexes with `regex`
/// (which may share compiled regexes between rules). The error names the
/// offending key.
pub fn build(
    spec: &PostSpec,
    stopwords: &BTreeMap<String, Vec<String>>,
    regex: &dyn Fn(&str) -> Result<Regex, regex::Error>,
) -> Result<Box<dyn Post>, (&'static str, String)> {
    let re = |key: &'static str, src: &str| regex(src).map_err(|e| (key, e.to_string()));
    Ok(match spec {
        PostSpec::Span { regex, group } => Box::new(Span::new(re("span_regex", regex)?, *group)),
        PostSpec::Entropy { min } => Box::new(Entropy { min: *min }),
        PostSpec::Stopwords { list } => {
            let words = stopwords
                .get(list)
                .ok_or(("stopwords", format!("list `{list}` not found")))?;
            Box::new(Stopwords::new(words))
        }
        PostSpec::AllowRegex { regex } => Box::new(AllowRegex::new(re("allow_regex", regex)?)),
        PostSpec::FloatRun { min_floats } => Box::new(FloatRun {
            min_floats: *min_floats,
        }),
        PostSpec::NpyHeader {
            min_dim,
            embedding_dims,
        } => Box::new(NpyHeader {
            min_dim: *min_dim,
            embedding_dims: embedding_dims.clone(),
        }),
        PostSpec::NpzMembers {
            min_dim,
            embedding_dims,
            exclude_name_regex,
            min_bank,
            min_bank_share,
        } => Box::new(NpzMembers {
            min_dim: *min_dim,
            embedding_dims: embedding_dims.clone(),
            exclude_name_regex: match exclude_name_regex {
                Some(s) => Some(re("exclude_name_regex", s)?),
                None => None,
            },
            min_bank: *min_bank,
            min_bank_share: *min_bank_share,
        }),
        PostSpec::SafetensorsHeader {
            min_dim,
            name_regex,
            embedding_dims,
            exclude_name_regex,
            min_bank,
            min_bank_share,
        } => Box::new(SafetensorsHeader {
            min_dim: *min_dim,
            name_regex: match name_regex {
                Some(s) => Some(re("name_regex", s)?),
                None => None,
            },
            embedding_dims: embedding_dims.clone(),
            exclude_name_regex: match exclude_name_regex {
                Some(s) => Some(re("exclude_name_regex", s)?),
                None => None,
            },
            min_bank: *min_bank,
            min_bank_share: *min_bank_share,
        }),
        PostSpec::FloatArray { embedding_dims } => Box::new(FloatArray {
            embedding_dims: embedding_dims.clone(),
        }),
    })
}
