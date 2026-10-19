//! Rule metadata: the scoring and post-processing contract carried in each
//! YARA rule's `meta:` section.

use crate::model::Category;
use crate::score::Tiers;
use std::fmt;
use yara_x::MetaValue;

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
#[derive(Debug, Clone, PartialEq)]
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
    NpyHeader {
        min_dim: u64,
    },
    NpzMembers {
        min_dim: u64,
    },
    SafetensorsHeader {
        min_dim: u64,
        name_regex: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuleMeta {
    pub category: Category,
    pub weight: f64,
    pub tiers: Option<Tiers>,
    pub family: Option<String>,
    pub family_cap: Option<f64>,
    pub post: Vec<PostSpec>,
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
        })
    }

    fn post_spec(raw: &Raw, name: &str) -> Result<PostSpec, MetaError> {
        Ok(match name {
            "span" => PostSpec::Span {
                regex: raw.need(raw.string("span_regex")?, "span_regex", name)?,
                group: raw.uint("secret_group")?.unwrap_or(0) as usize,
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
            "float_run" => PostSpec::FloatRun {
                min_floats: raw.need(raw.uint("min_floats")?, "min_floats", name)?,
            },
            "npy_header" => PostSpec::NpyHeader {
                min_dim: raw.need(raw.uint("min_dim")?, "min_dim", name)?,
            },
            "npz_members" => PostSpec::NpzMembers {
                min_dim: raw.need(raw.uint("min_dim")?, "min_dim", name)?,
            },
            "safetensors_header" => PostSpec::SafetensorsHeader {
                min_dim: raw.need(raw.uint("min_dim")?, "min_dim", name)?,
                name_regex: raw.string("name_regex")?,
            },
            other => return Err(raw.err(format_args!("unknown post-processor `{other}`"))),
        })
    }
}
