//! Dernier scan : enregistré sur disque pour être rechargé au lancement
//! et comparé au scan suivant (appareils nouveaux / disparus).

use crate::scanner::HostResult;
use std::path::PathBuf;

/// Différence d'un hôte par rapport au scan précédent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change {
    /// Actif maintenant, inactif au scan précédent.
    New,
    /// Actif au scan précédent, ne répond plus.
    Gone,
}

pub struct Saved {
    pub total: usize,
    pub elapsed_ms: u64,
    pub cancelled: bool,
    pub rows: Vec<(HostResult, Option<Change>)>,
}

const MAGIC: &str = "netscan-scan-1";

fn path() -> Option<PathBuf> {
    Some(eframe::storage_dir("NetScan")?.join("last_scan.tsv"))
}

pub fn encode<'a>(
    total: usize,
    elapsed_ms: u64,
    cancelled: bool,
    rows: impl Iterator<Item = (&'a HostResult, Option<Change>)>,
) -> String {
    let mut out = format!("{MAGIC}\t{total}\t{elapsed_ms}\t{}\n", u8::from(cancelled));
    for (h, change) in rows {
        out.push_str(match change {
            Some(Change::New) => "N\t",
            Some(Change::Gone) => "G\t",
            None => "-\t",
        });
        out.push_str(&h.to_line());
        out.push('\n');
    }
    out
}

pub fn decode(text: &str) -> Option<Saved> {
    let mut lines = text.lines();
    let head: Vec<&str> = lines.next()?.split('\t').collect();
    if head.len() != 4 || head[0] != MAGIC {
        return None;
    }
    let mut rows = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let (flag, rest) = line.split_once('\t')?;
        let change = match flag {
            "N" => Some(Change::New),
            "G" => Some(Change::Gone),
            _ => None,
        };
        rows.push((HostResult::from_line(rest)?, change));
    }
    Some(Saved {
        total: head[1].parse().ok()?,
        elapsed_ms: head[2].parse().ok()?,
        cancelled: head[3] == "1",
        rows,
    })
}

pub fn save(content: String) {
    if let Some(p) = path() {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(p, content);
    }
}

pub fn load() -> Option<Saved> {
    decode(&std::fs::read_to_string(path()?).ok()?)
}

pub fn delete() {
    if let Some(p) = path() {
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let a = HostResult::from_line("10.0.0.1\tP\tbox\t50A6D8010203\t3\t80,443\t2026-11-14 10:00:00").unwrap();
        let b = HostResult::from_line("10.0.0.2\t\tancien\t\t\t\t2026-11-14 10:00:01").unwrap();
        let text = encode(254, 1500, true, [(&a, Some(Change::New)), (&b, Some(Change::Gone))].into_iter());
        let s = decode(&text).unwrap();
        assert_eq!((s.total, s.elapsed_ms, s.cancelled, s.rows.len()), (254, 1500, true, 2));
        assert_eq!(s.rows[0].1, Some(Change::New));
        assert_eq!(s.rows[1].1, Some(Change::Gone));
        assert_eq!(s.rows[1].0.hostname.as_deref(), Some("ancien"));
        assert!(decode("autre chose").is_none());
    }
}
