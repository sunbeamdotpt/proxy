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

/// Only the Friday DDoS file — contains DDoS Hulk, Slowloris, slowhttptest, GoldenEye.
const CICIDS_FILE: &str = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv";

/// Hugging Face mirror (public, no auth required).
const CICIDS_BASE_URL: &str =
    "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main";

fn cicids_cache_dir() -> PathBuf {
    cache_base().join("cicids")
}

/// Return the path to the cached CIC-IDS2017 DDoS CSV, or `None` if not downloaded.
pub fn cicids_cached_path() -> Option<PathBuf> {
    let path = cicids_cache_dir().join(CICIDS_FILE);
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

/// Download the CIC-IDS2017 Friday DDoS CSV to cache.  Returns the cached path.
pub fn download_cicids() -> Result<PathBuf> {
    let dir = cicids_cache_dir();
    let path = dir.join(CICIDS_FILE);

    if path.exists() {
        eprintln!("  cached: {}", path.display());
        return Ok(path);
    }

    let url = format!("{CICIDS_BASE_URL}/{CICIDS_FILE}");
    eprintln!("  downloading: {url}");
    eprintln!("  (this is ~170 MB, may take a minute)");

    std::fs::create_dir_all(&dir)?;

    // Stream to file to avoid holding 170MB in memory.
    let resp = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()?
        .get(&url)
        .send()
        .with_context(|| format!("fetching {url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error for {url}"))?;

    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    let bytes = resp.bytes().with_context(|| "reading response body")?;
    std::io::Write::write_all(&mut file, &bytes)?;

    eprintln!("  saved: {}", path.display());
    Ok(path)
}

// --- CSIC 2010 ---

/// Download CSIC 2010 dataset files to cache (delegates to scanner::csic).
pub fn download_csic() -> Result<()> {
    if crate::scanner::csic::csic_is_cached() {
        eprintln!("  cached: {}", crate::scanner::csic::csic_cache_path().display());
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

    eprintln!("[2/2] CIC-IDS2017 DDoS timing profiles");
    let path = download_cicids()?;
    eprintln!("  ok: {}\n", path.display());

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
}
