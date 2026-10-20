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
pub use words::Stopwords;

#[derive(Debug, Clone, PartialEq)]
pub enum PostResult {
    Keep(Range<usize>),
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
        } => Box::new(NpzMembers {
            min_dim: *min_dim,
            embedding_dims: embedding_dims.clone(),
        }),
        PostSpec::SafetensorsHeader {
            min_dim,
            name_regex,
            embedding_dims,
            exclude_name_regex,
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
        }),
        PostSpec::FloatArray { embedding_dims } => Box::new(FloatArray {
            embedding_dims: embedding_dims.clone(),
        }),
    })
}
