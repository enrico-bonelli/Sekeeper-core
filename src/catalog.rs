//! The revision graph of a synchronized vault. Every copy carries an
//! authenticated revision with its parents, plus a compact lineage of older
//! revisions, so the current version can be found even after old copies are
//! deleted. Missing links, contradictions and cycles always fail closed.

use crate::limits::{self, MAX_HISTORY_BYTES, MAX_LINEAGE, MAX_VERSIONS};
use crate::model::{Credential, Revision, RevisionLink};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct CatalogError(pub String);

fn error(message: &str) -> CatalogError {
    CatalogError(message.into())
}

pub type Result<T> = std::result::Result<T, CatalogError>;

#[derive(Clone)]
pub struct Snapshot {
    pub id: String,
    pub bytes: Vec<u8>,
    pub revision: Revision,
}

pub struct Catalog {
    pub snapshots: BTreeMap<String, Snapshot>,
    /// Revisions without descendants: one when the history is linear.
    pub heads: Vec<String>,
    /// Every known revision and its sorted parents.
    pub links: BTreeMap<String, Vec<String>>,
    /// Reverse topological rank: descendants first, newest branch first.
    pub order: BTreeMap<String, usize>,
}

pub enum Decision {
    Current,
    FastForward(String),
    Conflict,
}

impl Catalog {
    /// Validates the copies with `read`, which must authenticate each one and
    /// return its revision and lineage, then builds the revision graph.
    pub fn assemble<E>(
        copies: Vec<(String, Vec<u8>)>,
        read: impl Fn(&[u8]) -> std::result::Result<(Revision, Vec<RevisionLink>), E>,
    ) -> Result<Self> {
        let mut snapshots: BTreeMap<String, Snapshot> = BTreeMap::new();
        let mut size = 0usize;
        let mut links = BTreeMap::new();
        for (id, bytes) in copies {
            if let Some(previous) = snapshots.get(&id) {
                if previous.bytes != bytes {
                    return Err(error(
                        "copie diverse hanno lo stesso identificativo; sincronizzazione interrotta",
                    ));
                }
                continue;
            }
            size += bytes.len();
            if snapshots.len() >= MAX_VERSIONS || size > MAX_HISTORY_BYTES {
                return Err(error(
                    "storico troppo grande: archivia alcune copie prima di sincronizzare",
                ));
            }
            let (revision, ancestry) = read(&bytes).map_err(|_| error(
                "una copia S3 è danneggiata o appartiene a un altro vault: verifica il prefisso scelto; nessuna copia locale è stata sostituita"))?;
            if revision.id != id {
                return Err(error(
                    "identificativo S3 non corrispondente al contenuto autenticato",
                ));
            }
            for link in ancestry {
                merge_link(&mut links, &link.id, &link.parents)?;
            }
            merge_link(&mut links, &revision.id, &revision.parents)?;
            snapshots.insert(
                id.clone(),
                Snapshot {
                    id,
                    bytes,
                    revision,
                },
            );
        }
        if snapshots.is_empty() {
            return Err(error("nessuna copia versionata disponibile"));
        }
        // The small, authenticated links replace complete historical vaults.
        // Missing links, contradictions, cycles and detached fabricated nodes
        // still fail closed, even when all remaining snapshots decrypt.
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut pending = BTreeMap::new();
        for (id, parents) in &links {
            pending.insert(id.clone(), parents.len());
            for parent in parents {
                if !links.contains_key(parent) {
                    return Err(error(
                        "storico incompleto: manca una versione precedente; nessun vault è stato sostituito",
                    ));
                }
                children.entry(parent.clone()).or_default().push(id.clone());
            }
        }
        let mut ready: Vec<String> = pending
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(id, _)| id.clone())
            .collect();
        let mut visited = 0usize;
        while let Some(id) = ready.pop() {
            visited += 1;
            if let Some(next) = children.get(&id) {
                for child in next {
                    let count = pending.get_mut(child).expect("nodo verificato");
                    *count -= 1;
                    if *count == 0 {
                        ready.push(child.clone());
                    }
                }
            }
        }
        if visited != links.len() {
            return Err(error("relazioni tra versioni non valide"));
        }
        let heads: Vec<String> = links
            .keys()
            .filter(|id| !children.contains_key(*id))
            .cloned()
            .collect();
        if heads.iter().any(|id| !snapshots.contains_key(id)) {
            return Err(error(
                "storico incompleto: manca il contenuto di una versione corrente",
            ));
        }
        // Reverse topological order: descendants always precede their ancestors,
        // while authenticated dates choose between independent branches. This
        // keeps a fresh short offline branch ahead of an old long branch.
        let mut remaining: BTreeMap<String, usize> = links
            .keys()
            .map(|id| (id.clone(), children.get(id).map_or(0, Vec::len)))
            .collect();
        let date = |id: &String| snapshots.get(id).map_or(0, |s| s.revision.created_at);
        let mut ready: BTreeSet<(u64, String)> =
            heads.iter().map(|id| (date(id), id.clone())).collect();
        let mut order = BTreeMap::new();
        while let Some((_, id)) = ready.pop_last() {
            order.insert(id.clone(), order.len());
            for parent in &links[&id] {
                let count = remaining.get_mut(parent).expect("genitore verificato");
                *count -= 1;
                if *count == 0 {
                    ready.insert((date(parent), parent.clone()));
                }
            }
        }
        Ok(Self {
            snapshots,
            heads,
            links,
            order,
        })
    }

    pub fn decision(&self, local: &str) -> Decision {
        match self.heads.as_slice() {
            [head] if head == local => Decision::Current,
            [head] if self.descends_from(head, local) => Decision::FastForward(head.clone()),
            _ => Decision::Conflict,
        }
    }

    pub fn descends_from(&self, head: &str, ancestor: &str) -> bool {
        let mut todo = vec![head.to_string()];
        let mut seen = BTreeSet::new();
        while let Some(id) = todo.pop() {
            if id == ancestor {
                return true;
            }
            if seen.insert(id.clone())
                && let Some(parents) = self.links.get(&id)
            {
                todo.extend(parents.iter().cloned());
            }
        }
        false
    }

    pub fn copies(&self) -> Vec<(String, Vec<u8>)> {
        self.snapshots
            .values()
            .map(|s| (s.id.clone(), s.bytes.clone()))
            .collect()
    }
}

pub fn merge_link(
    links: &mut BTreeMap<String, Vec<String>>,
    id: &str,
    parents: &[String],
) -> Result<()> {
    let mut parents = parents.to_vec();
    parents.sort();
    parents.dedup();
    if let Some(previous) = links.get(id) {
        if *previous != parents {
            return Err(error("collegamenti autenticati in contraddizione"));
        }
    } else {
        if links.len() >= MAX_LINEAGE + MAX_VERSIONS {
            return Err(error("troppi collegamenti nello storico"));
        }
        if !limits::valid_id(id) {
            return Err(error("identificativo di versione non valido"));
        }
        links.insert(id.to_string(), parents);
    }
    Ok(())
}

/// Entries that differ between the local vault and another version, by name.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct VersionDiff {
    /// Only in the other version.
    pub added: Vec<String>,
    /// Only in the local vault.
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

pub fn compare(local: &[Credential], other: &[Credential]) -> VersionDiff {
    let mut diff = VersionDiff::default();
    for entry in other {
        match local.iter().find(|item| item.id == entry.id) {
            None => diff.added.push(entry.description.clone()),
            Some(item) if !item.same_content(entry) => diff.changed.push(entry.description.clone()),
            Some(_) => {}
        }
    }
    diff.removed = local
        .iter()
        .filter(|item| !other.iter().any(|entry| entry.id == item.id))
        .map(|item| item.description.clone())
        .collect();
    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> String {
        format!("{n:032x}")
    }

    fn copy(n: u8, parents: &[u8], date: u64) -> (String, Vec<u8>) {
        let revision = Revision {
            vault_id: String::new(),
            id: id(n),
            parents: parents.iter().map(|p| id(*p)).collect(),
            created_at: date,
            device: String::new(),
        };
        (id(n), serde_json::to_vec(&revision).unwrap())
    }

    fn assemble(copies: Vec<(String, Vec<u8>)>) -> Result<Catalog> {
        Catalog::assemble(copies, |bytes| {
            serde_json::from_slice::<Revision>(bytes).map(|revision| (revision, Vec::new()))
        })
    }

    #[test]
    fn linear_history_has_one_head_and_branches_are_conflicts() {
        let linear = assemble(vec![copy(1, &[], 1), copy(2, &[1], 2), copy(3, &[2], 3)]).unwrap();
        assert_eq!(linear.heads, vec![id(3)]);
        assert!(matches!(linear.decision(&id(3)), Decision::Current));
        assert!(matches!(linear.decision(&id(1)), Decision::FastForward(head) if head == id(3)));
        let forked = assemble(vec![copy(1, &[], 1), copy(2, &[1], 2), copy(3, &[1], 9)]).unwrap();
        assert_eq!(forked.heads.len(), 2);
        assert!(matches!(forked.decision(&id(2)), Decision::Conflict));
        // The newer branch comes first, whatever its length.
        assert!(forked.order[&id(3)] < forked.order[&id(2)]);
    }

    #[test]
    fn incomplete_contradictory_or_unreadable_histories_fail_closed() {
        assert!(assemble(vec![copy(2, &[1], 2)]).is_err());
        assert!(assemble(Vec::new()).is_err());
        let mut forged = copy(2, &[], 2);
        forged.0 = id(7);
        assert!(assemble(vec![forged]).is_err());
        assert!(
            Catalog::assemble(vec![copy(1, &[], 1)], |_| Err::<
                (Revision, Vec<RevisionLink>),
                (),
            >(()))
            .is_err()
        );
    }
}
