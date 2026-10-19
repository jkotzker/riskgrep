//! Post-processors: Rust refinements applied to each YARA match.

mod entropy;
mod span;
mod tensor;
mod words;

use crate::meta::PostSpec;
use crate::model::ShapeFacts;
use regex::bytes::{Regex, RegexBuilder};
use std::collections::BTreeMap;
use std::ops::Range;

pub use entropy::Entropy;
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
}

/// Compile a regex with the bundle-wide settings.
pub fn compile_regex(src: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(src)
        .unicode(false)
        .size_limit(1 << 28)
        .build()
}

/// Build the processor for one spec. The error names the offending key.
pub fn build(
    spec: &PostSpec,
    stopwords: &BTreeMap<String, Vec<String>>,
) -> Result<Box<dyn Post>, (&'static str, String)> {
    let re = |key: &'static str, src: &str| compile_regex(src).map_err(|e| (key, e.to_string()));
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
        PostSpec::NpyHeader { min_dim } => Box::new(NpyHeader { min_dim: *min_dim }),
        PostSpec::NpzMembers { min_dim } => Box::new(NpzMembers { min_dim: *min_dim }),
        PostSpec::SafetensorsHeader {
            min_dim,
            name_regex,
        } => Box::new(SafetensorsHeader {
            min_dim: *min_dim,
            name_regex: match name_regex {
                Some(s) => Some(re("name_regex", s)?),
                None => None,
            },
        }),
    })
}
