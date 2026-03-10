// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Download and cache upstream datasets for training.
//!
//! Cached under `~/.cache/sunbeam/<dataset>/`.  Files are only downloaded
//! once; subsequent runs reuse the cached copy.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Base cache directory for all sunbeam datasets.
fn cache_base() -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".cache")
        });
    base.join("sunbeam")
}

// --- CIC-IDS2017 ---

/// All CIC-IDS2017 CSV files — covers every attack day and normal baselines.
const CICIDS_FILES: &[&str] = &[
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
];

/// Hugging Face mirror (public, no auth required).
const CICIDS_BASE_URL: &str =
    "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main";

fn cicids_cache_dir() -> PathBuf {
    cache_base().join("cicids")
}

/// Return the cache directory if ALL CIC-IDS2017 CSVs are downloaded, else `None`.
pub fn cicids_cached_path() -> Option<PathBuf> {
    let dir = cicids_cache_dir();
    if CICIDS_FILES.iter().all(|f| dir.join(f).exists()) {
        Some(dir)
    } else {
        None
    }
}

/// Download all CIC-IDS2017 CSV files to cache. Returns the cache directory.
pub fn download_cicids() -> Result<PathBuf> {
    let dir = cicids_cache_dir();
    std::fs::create_dir_all(&dir)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()?;

    for (i, filename) in CICIDS_FILES.iter().enumerate() {
        let path = dir.join(filename);
        if path.exists() {
            eprintln!("  [{}/{}] cached: {}", i + 1, CICIDS_FILES.len(), filename);
            continue;
        }

        let url = format!("{CICIDS_BASE_URL}/{filename}");
        eprintln!(
            "  [{}/{}] downloading: {}",
            i + 1,
            CICIDS_FILES.len(),
            filename
        );

        let resp = client
            .get(&url)
            .send()
            .with_context(|| format!("fetching {url}"))?
            .error_for_status()
            .with_context(|| format!("HTTP error for {url}"))?;

        let mut file = std::fs::File::create(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        let bytes = resp.bytes().with_context(|| "reading response body")?;
        std::io::Write::write_all(&mut file, &bytes)?;

        eprintln!("    saved: {}", path.display());
    }

    Ok(dir)
}

// --- CSIC 2010 ---

/// Download CSIC 2010 dataset files to cache (delegates to scanner::csic).
pub fn download_csic() -> Result<()> {
    if crate::scanner::csic::csic_is_cached() {
        eprintln!(
            "  cached: {}",
            crate::scanner::csic::csic_cache_path().display()
        );
        return Ok(());
    }
    // fetch_csic_dataset downloads, caches, and parses — we only need the download side-effect.
    crate::scanner::csic::fetch_csic_dataset()?;
    Ok(())
}

/// Download all upstream datasets.
pub fn download_all() -> Result<()> {
    eprintln!("downloading upstream datasets...\n");

    eprintln!("[1/2] CSIC 2010 (scanner training data)");
    download_csic()?;
    eprintln!();

    eprintln!("[2/2] CIC-IDS2017 (all attack days + normal baselines)");
    let path = download_cicids()?;
    eprintln!("  ok: {} ({} files)\n", path.display(), CICIDS_FILES.len());

    eprintln!("all datasets cached.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_paths() {
        let base = cache_base();
        assert!(base.to_str().unwrap().contains("sunbeam"));

        let cicids = cicids_cache_dir();
        assert!(cicids.to_str().unwrap().contains("cicids"));
    }

    #[test]
    fn test_all_files_listed() {
        assert_eq!(CICIDS_FILES.len(), 8);
        assert!(CICIDS_FILES.iter().all(|f| f.ends_with(".csv")));
    }
}
