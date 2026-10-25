//! Rule metadata: the scoring and post-processing contract carried in each
//! YARA rule's `meta:` section.

use crate::model::Category;
use crate::score::Tiers;
use serde::{Deserialize, Serialize};
use std::fmt;
use yara_x::MetaValue;

/// `PostSpec::Span` group value for `secret_group = "first_nonempty"`:
/// gitleaks' default secret, the first capture group that took part in the
/// match and is non-empty, else the whole match.
pub const FIRST_NONEMPTY_GROUP: usize = usize::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaError(pub String);

impl fmt::Display for MetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MetaError {}

/// A post-processor and its arguments. Regexes are stored as source text and
/// compiled by the scan engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "post", rename_all = "snake_case", deny_unknown_fields)]
pub enum PostSpec {
    Span {
        regex: String,
        group: usize,
    },
    Entropy {
        min: f64,
    },
    Stopwords {
        list: String,
    },
    AllowRegex {
        regex: String,
    },
    FloatRun {
        min_floats: u64,
    },
    CodeLines {
        min_codes: u64,
    },
    NpyHeader {
        min_dim: u64,
        embedding_dims: Option<Vec<u64>>,
    },
    NpzMembers {
        min_dim: u64,
        embedding_dims: Option<Vec<u64>>,
        exclude_name_regex: Option<String>,
        min_bank: Option<u64>,
        min_bank_share: Option<u64>,
    },
    SafetensorsHeader {
        min_dim: u64,
        name_regex: Option<String>,
        embedding_dims: Option<Vec<u64>>,
        exclude_name_regex: Option<String>,
        min_bank: Option<u64>,
        min_bank_share: Option<u64>,
    },
    FloatArray {
        embedding_dims: Vec<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMeta {
    pub category: Category,
    pub weight: f64,
    pub tiers: Option<Tiers>,
    pub family: Option<String>,
    pub family_cap: Option<f64>,
    pub post: Vec<PostSpec>,
    /// Meta `line_complete = true`: the rule's locations cover every match,
    /// each within its own lines, so a partial read that avoids them cannot
    /// show a match. Used by the Claude Code hook's partial reads.
    #[serde(default)]
    pub line_complete: bool,
}

struct Raw<'a> {
    rule: &'a str,
    items: Vec<(&'a str, MetaValue<'a>)>,
}

impl<'a> Raw<'a> {
    fn err(&self, msg: impl fmt::Display) -> MetaError {
        MetaError(format!("rule {}: {msg}", self.rule))
    }

    fn get(&self, key: &str) -> Option<&MetaValue<'a>> {
        self.items.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    fn string(&self, key: &str) -> Result<Option<String>, MetaError> {
        match self.get(key) {
            None => Ok(None),
            Some(MetaValue::String(s)) => Ok(Some((*s).to_string())),
            // YARA-X stores a literal containing escapes (regexes) as bytes.
            Some(MetaValue::Bytes(b)) => match std::str::from_utf8(b) {
                Ok(s) => Ok(Some(s.to_string())),
                Err(_) => Err(self.err(format_args!("`{key}` must be a string"))),
            },
            Some(_) => Err(self.err(format_args!("`{key}` must be a string"))),
        }
    }

    fn number(&self, key: &str) -> Result<Option<f64>, MetaError> {
        match self.get(key) {
            None => Ok(None),
            Some(MetaValue::Integer(i)) => Ok(Some(*i as f64)),
            Some(MetaValue::Float(f)) => Ok(Some(*f)),
            Some(_) => Err(self.err(format_args!("`{key}` must be a number"))),
        }
    }

    fn uint(&self, key: &str) -> Result<Option<u64>, MetaError> {
        match self.get(key) {
            None => Ok(None),
            Some(MetaValue::Integer(i)) if *i >= 0 => Ok(Some(*i as u64)),
            Some(_) => Err(self.err(format_args!("`{key}` must be an integer >= 0"))),
        }
    }

    /// A comma-separated list of positive integers (`embedding_dims`).
    fn dims(&self, key: &str) -> Result<Option<Vec<u64>>, MetaError> {
        let Some(s) = self.string(key)? else {
            return Ok(None);
        };
        let dims: Option<Vec<u64>> = s
            .split(',')
            .map(|d| d.trim().parse::<u64>().ok().filter(|&n| n > 0))
            .collect();
        match dims {
            Some(v) if !v.is_empty() => Ok(Some(v)),
            _ => Err(self.err(format_args!(
                "`{key}` must be a comma-separated list of positive integers"
            ))),
        }
    }

    /// `min_bank` (at least 2) and `min_bank_share` (a percentage, 1 to 99,
    /// only with `min_bank`; the bank must exceed it).
    fn bank(&self) -> Result<(Option<u64>, Option<u64>), MetaError> {
        let min = self.uint("min_bank")?;
        if min.is_some_and(|n| n < 2) {
            return Err(self.err("`min_bank` must be at least 2"));
        }
        let share = self.uint("min_bank_share")?;
        match share {
            Some(s) if !(1..=99).contains(&s) => {
                Err(self.err("`min_bank_share` must be a percentage from 1 to 99"))
            }
            Some(_) if min.is_none() => Err(self.err("`min_bank_share` requires `min_bank`")),
            _ => Ok((min, share)),
        }
    }

    /// `secret_group`: a capture group index (default 0, the whole match) or
    /// `"first_nonempty"` ([`FIRST_NONEMPTY_GROUP`]).
    fn secret_group(&self) -> Result<usize, MetaError> {
        match self.get("secret_group") {
            None => Ok(0),
            Some(MetaValue::Integer(i)) if *i >= 0 => Ok(*i as usize),
            Some(MetaValue::String("first_nonempty")) => Ok(FIRST_NONEMPTY_GROUP),
            Some(_) => {
                Err(self.err("`secret_group` must be an integer >= 0 or \"first_nonempty\""))
            }
        }
    }

    fn boolean(&self, key: &str) -> Result<Option<bool>, MetaError> {
        match self.get(key) {
            None => Ok(None),
            Some(MetaValue::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(self.err(format_args!("`{key}` must be true or false"))),
        }
    }

    fn need<T>(&self, v: Option<T>, key: &str, post: &str) -> Result<T, MetaError> {
        v.ok_or_else(|| self.err(format_args!("post `{post}` requires key `{key}`")))
    }
}

impl RuleMeta {
    pub fn from_yara(rule: &yara_x::Rule) -> Result<RuleMeta, MetaError> {
        let raw = Raw {
            rule: rule.identifier(),
            items: rule.metadata().collect(),
        };

        let category = raw
            .string("category")?
            .ok_or_else(|| raw.err("missing required key `category`"))?;
        let weight = raw
            .number("weight")?
            .ok_or_else(|| raw.err("missing required key `weight`"))?;
        if !(-100.0..=100.0).contains(&weight) {
            return Err(raw.err(format_args!("`weight` {weight} outside -100..=100")));
        }
        let tiers = match raw.string("tiers")? {
            None => None,
            Some(s) => Some(s.parse::<Tiers>().map_err(|e| raw.err(e))?),
        };
        let family = raw.string("family")?;
        let family_cap = raw.number("family_cap")?;
        if let Some(c) = family_cap {
            if !(0.0..=100.0).contains(&c) {
                return Err(raw.err(format_args!("`family_cap` {c} outside 0..=100")));
            }
        }

        let mut post = Vec::new();
        if let Some(list) = raw.string("post")? {
            for name in list.split(',').map(str::trim) {
                post.push(Self::post_spec(&raw, name)?);
            }
        }

        Ok(RuleMeta {
            category: Category(category),
            weight,
            tiers,
            family,
            family_cap,
            post,
            line_complete: raw.boolean("line_complete")?.unwrap_or(false),
        })
    }

    fn post_spec(raw: &Raw, name: &str) -> Result<PostSpec, MetaError> {
        Ok(match name {
            "span" => PostSpec::Span {
                regex: raw.need(raw.string("span_regex")?, "span_regex", name)?,
                group: raw.secret_group()?,
            },
            "entropy" => PostSpec::Entropy {
                min: raw.need(raw.number("min_entropy")?, "min_entropy", name)?,
            },
            "stopwords" => PostSpec::Stopwords {
                list: raw.need(raw.string("stopwords")?, "stopwords", name)?,
            },
            "allow_regex" => PostSpec::AllowRegex {
                regex: raw.need(raw.string("allow_regex")?, "allow_regex", name)?,
            },
            "code_lines" => PostSpec::CodeLines {
                min_codes: raw.need(raw.uint("min_codes")?, "min_codes", name)?,
            },
            "float_run" => PostSpec::FloatRun {
                min_floats: raw.need(raw.uint("min_floats")?, "min_floats", name)?,
            },
            "npy_header" => PostSpec::NpyHeader {
                min_dim: raw.need(raw.uint("min_dim")?, "min_dim", name)?,
                embedding_dims: raw.dims("embedding_dims")?,
            },
            "npz_members" => {
                let (min_bank, min_bank_share) = raw.bank()?;
                PostSpec::NpzMembers {
                    min_dim: raw.need(raw.uint("min_dim")?, "min_dim", name)?,
                    embedding_dims: raw.dims("embedding_dims")?,
                    exclude_name_regex: raw.string("exclude_name_regex")?,
                    min_bank,
                    min_bank_share,
                }
            }
            "safetensors_header" => {
                let (min_bank, min_bank_share) = raw.bank()?;
                PostSpec::SafetensorsHeader {
                    min_dim: raw.need(raw.uint("min_dim")?, "min_dim", name)?,
                    name_regex: raw.string("name_regex")?,
                    embedding_dims: raw.dims("embedding_dims")?,
                    exclude_name_regex: raw.string("exclude_name_regex")?,
                    min_bank,
                    min_bank_share,
                }
            }
            "float_array" => PostSpec::FloatArray {
                embedding_dims: raw.need(raw.dims("embedding_dims")?, "embedding_dims", name)?,
            },
            other => return Err(raw.err(format_args!("unknown post-processor `{other}`"))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(secret_group: &str) -> Result<RuleMeta, MetaError> {
        let src = format!(
            "rule r {{ meta: category = \"secret\" weight = 80 post = \"span\" \
             span_regex = \"k=([0-9]+)\"{secret_group} condition: true }}"
        );
        let rules = yara_x::compile(src.as_str()).unwrap();
        let rule = rules.iter().next().unwrap();
        RuleMeta::from_yara(&rule)
    }

    fn group(m: &RuleMeta) -> usize {
        match &m.post[0] {
            PostSpec::Span { group, .. } => *group,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn secret_group_integer_or_first_nonempty() {
        assert_eq!(group(&parse("").unwrap()), 0);
        assert_eq!(group(&parse(" secret_group = 2").unwrap()), 2);
        assert_eq!(
            group(&parse(" secret_group = \"first_nonempty\"").unwrap()),
            FIRST_NONEMPTY_GROUP
        );
    }

    fn rule(meta: &str) -> Result<RuleMeta, MetaError> {
        let src =
            format!("rule r {{ meta: category = \"secret\" weight = 80{meta} condition: true }}");
        let rules = yara_x::compile(src.as_str()).unwrap();
        let rule = rules.iter().next().unwrap();
        RuleMeta::from_yara(&rule)
    }

    #[test]
    fn line_complete_is_an_explicit_boolean() {
        assert!(!rule("").unwrap().line_complete);
        assert!(rule(" line_complete = true").unwrap().line_complete);
        assert!(!rule(" line_complete = false").unwrap().line_complete);
        for bad in [" line_complete = 1", " line_complete = \"yes\""] {
            let e = rule(bad).unwrap_err();
            assert!(e.0.contains("line_complete"), "{bad}: {e}");
        }
    }

    #[test]
    fn secret_group_rejects_other_values() {
        for bad in [
            " secret_group = -1",
            " secret_group = \"first\"",
            " secret_group = 1.5",
        ] {
            let e = parse(bad).unwrap_err();
            assert!(e.0.contains("secret_group"), "{bad}: {e}");
        }
    }
}
