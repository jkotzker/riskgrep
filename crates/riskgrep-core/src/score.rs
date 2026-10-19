//! Noisy-or scorer. Per category: positive weights combine as
//! `1 - prod(1 - p)`, families are capped, negative weights dampen.

use crate::meta::RuleMeta;
use crate::model::{Category, Evidence};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;

/// Count-to-weight tiers, ascending by threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct Tiers(Vec<(u32, f64)>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TiersError(pub String);

impl fmt::Display for TiersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid tiers: {}", self.0)
    }
}

impl std::error::Error for TiersError {}

impl FromStr for Tiers {
    type Err = TiersError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out: Vec<(u32, f64)> = Vec::new();
        for part in s.split(',') {
            let (t, w) = part
                .trim()
                .split_once(':')
                .ok_or_else(|| TiersError(format!("expected threshold:weight, got {part:?}")))?;
            let t: u32 = t
                .trim()
                .parse()
                .map_err(|_| TiersError(format!("bad threshold {t:?}")))?;
            let w: f64 = w
                .trim()
                .parse()
                .map_err(|_| TiersError(format!("bad weight {w:?}")))?;
            if !(-100.0..=100.0).contains(&w) {
                return Err(TiersError(format!("weight {w} outside -100..=100")));
            }
            if let Some(&(prev, _)) = out.last() {
                if t <= prev {
                    return Err(TiersError("thresholds must be strictly ascending".into()));
                }
            }
            out.push((t, w));
        }
        Ok(Tiers(out))
    }
}

impl fmt::Display for Tiers {
    /// The `threshold:weight,...` form [`FromStr`] reads.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (t, w)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{t}:{w}")?;
        }
        Ok(())
    }
}

impl Serialize for Tiers {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Tiers {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Tiers {
    /// Weight of the largest threshold <= `count`; 0.0 below the first.
    pub fn weight_for(&self, count: u32) -> f64 {
        self.0
            .iter()
            .rev()
            .find(|(t, _)| *t <= count)
            .map_or(0.0, |&(_, w)| w)
    }
}

#[derive(Debug, Clone)]
pub struct Contribution {
    pub rule: String,
    pub category: Category,
    pub weight: f64,
    pub count: u32,
    pub tiers: Option<Tiers>,
    pub family: Option<String>,
    pub family_cap: Option<f64>,
}

impl Contribution {
    fn effective_weight(&self) -> f64 {
        match &self.tiers {
            Some(t) => t.weight_for(self.count),
            None => self.weight,
        }
    }
}

#[derive(Default)]
struct CategoryAcc {
    /// 1 - p products per family, plus the family's cap.
    families: BTreeMap<String, (f64, Option<f64>)>,
    /// Product of (1 - p) over ungrouped positive rules.
    ungrouped: f64,
    /// Product of (1 - |n|/100) over negative weights.
    damp: f64,
}

/// Unrounded score per category; categories with no contribution get no entry.
pub fn score(contribs: &[Contribution]) -> BTreeMap<Category, f64> {
    let mut acc: BTreeMap<&Category, CategoryAcc> = BTreeMap::new();
    for c in contribs {
        let a = acc.entry(&c.category).or_insert_with(|| CategoryAcc {
            ungrouped: 1.0,
            damp: 1.0,
            ..Default::default()
        });
        let w = c.effective_weight();
        if w < 0.0 {
            a.damp *= 1.0 - (-w) / 100.0;
        } else if let Some(fam) = &c.family {
            let e = a.families.entry(fam.clone()).or_insert((1.0, None));
            e.0 *= 1.0 - w / 100.0;
            if c.family_cap.is_some() {
                e.1 = c.family_cap;
            }
        } else {
            a.ungrouped *= 1.0 - w / 100.0;
        }
    }
    acc.into_iter()
        .map(|(cat, a)| {
            let mut miss = a.ungrouped;
            for (prod, cap) in a.families.values() {
                let mut combined = 1.0 - prod;
                if let Some(cap) = cap {
                    combined = combined.min(cap / 100.0);
                }
                miss *= 1.0 - combined;
            }
            (cat.clone(), 100.0 * (1.0 - miss) * a.damp)
        })
        .collect()
}

/// Scores of one target's evidence. `meta` is keyed `namespace:rule`; the
/// weight, tiers, and family come from it (so weight overrides apply), and
/// evidence whose rule has no metadata scores with its own weight alone.
/// Bare rule ids are assumed unique across `meta`'s namespaces.
pub fn score_target(
    evidence: &[Evidence],
    meta: &HashMap<String, RuleMeta>,
) -> BTreeMap<Category, f64> {
    let by_rule: HashMap<&str, &RuleMeta> = meta
        .iter()
        .filter_map(|(k, m)| k.split_once(':').map(|(_, rule)| (rule, m)))
        .collect();
    let contribs: Vec<Contribution> = evidence
        .iter()
        .map(|e| match by_rule.get(e.rule.as_str()) {
            Some(m) => Contribution {
                rule: e.rule.clone(),
                category: e.category.clone(),
                weight: m.weight,
                count: e.count,
                tiers: m.tiers.clone(),
                family: m.family.clone(),
                family_cap: m.family_cap,
            },
            None => Contribution {
                rule: e.rule.clone(),
                category: e.category.clone(),
                weight: e.weight,
                count: e.count,
                tiers: None,
                family: None,
                family_cap: None,
            },
        })
        .collect();
    score(&contribs)
}
