// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Thin parser wrapper around `caddyfile-rs`.

use std::path::{Path, PathBuf};

use crate::ir::RouteTable;

/// Error returned when a Caddyfile cannot be parsed or read.
#[derive(Debug)]
pub enum ParseError {
    /// Failed to read a file from disk.
    Read {
        /// Path that failed.
        path: PathBuf,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// Failed to parse Caddyfile syntax.
    Syntax { path: PathBuf, message: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Read { path, source } => write!(f, "reading {}: {source}", path.display()),
            ParseError::Syntax { path, message } => {
                write!(f, "parsing {}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Read { source, .. } => Some(source),
            ParseError::Syntax { .. } => None,
        }
    }
}

/// Parse a single Caddyfile into an [`ir::RouteTable`].
pub fn parse_file(path: &Path) -> Result<RouteTable, ParseError> {
    let raw = std::fs::read_to_string(path).map_err(|source| ParseError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse_str(path, &raw)
}

/// Parse all `*.caddyfile` and `Caddyfile` files in a directory.
///
/// Files are read in alphabetical order and merged into a single
/// [`ir::RouteTable`]. Subdirectories are ignored.
pub fn parse_dir(dir: &Path) -> Result<RouteTable, ParseError> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|source| ParseError::Read {
            path: dir.to_path_buf(),
            source,
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && is_caddyfile(p))
        .collect();

    entries.sort();

    let mut table = RouteTable::default();
    for path in entries {
        let file_table = parse_file(&path)?;
        merge_tables(&mut table, file_table);
    }
    Ok(table)
}

fn is_caddyfile(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    name == "Caddyfile" || name.ends_with(".caddyfile")
}

fn parse_str(path: &Path, raw: &str) -> Result<RouteTable, ParseError> {
    let caddyfile = caddyfile_rs::parse_str(raw).map_err(|e| ParseError::Syntax {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    crate::caddyfile::translate(&caddyfile).map_err(|e| ParseError::Syntax {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}

fn merge_tables(into: &mut RouteTable, other: RouteTable) {
    into.listeners.extend(other.listeners);
    into.hosts.extend(other.hosts);
    into.acme_routes.extend(other.acme_routes);
    into.l4_routes.extend(other.l4_routes);
    into.tls_certs.extend(other.tls_certs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file_valid_caddyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Caddyfile");
        std::fs::write(&path, "example.com {\n\tfile_server\n}\n").unwrap();

        let table = parse_file(&path).unwrap();
        assert_eq!(table.hosts.len(), 1);
    }

    #[test]
    fn parse_file_missing_file_errors() {
        let path = Path::new("/does/not/exist/Caddyfile");
        let err = parse_file(path).unwrap_err();
        assert!(format!("{err}").contains("reading"));
    }

    #[test]
    fn parse_file_invalid_syntax_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Caddyfile");
        let _ = std::fs::write(&path, "{ { { { "); // unbalanced braces

        let err = parse_file(&path).unwrap_err();
        assert!(format!("{err}").contains("parsing"));
    }

    #[test]
    fn parse_dir_loads_caddyfiles_alphabetically() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("001.caddyfile"),
            "a.example.com {\n\tfile_server\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("002.caddyfile"),
            "b.example.com {\n\tfile_server\n}\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("README.md"), "not a caddyfile").unwrap();

        let table = parse_dir(dir.path()).unwrap();
        assert_eq!(table.hosts.len(), 2);
        assert_eq!(
            table.hosts[0].hostname,
            crate::ir::HostnameMatch::Exact("a.example.com".into())
        );
        assert_eq!(
            table.hosts[1].hostname,
            crate::ir::HostnameMatch::Exact("b.example.com".into())
        );
    }

    #[test]
    fn parse_dir_ignores_non_caddyfiles() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("notes.txt"),
            "example.com {\n\tfile_server\n}\n",
        )
        .unwrap();

        let table = parse_dir(dir.path()).unwrap();
        assert!(table.hosts.is_empty());
    }

    #[test]
    fn parse_dir_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let table = parse_dir(dir.path()).unwrap();
        assert!(table.hosts.is_empty());
        assert!(table.listeners.is_empty());
    }

    #[test]
    fn parse_dir_missing_directory_errors() {
        let err = parse_dir(Path::new("/does/not/exist")).unwrap_err();
        assert!(format!("{err}").contains("reading"));
    }

    #[test]
    fn parse_error_source_returns_io_error() {
        use std::error::Error;
        let err = parse_file(Path::new("/does/not/exist/Caddyfile")).unwrap_err();
        assert!(err.source().is_some());
    }

    #[test]
    fn parse_error_syntax_has_no_source() {
        use std::error::Error;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Caddyfile");
        std::fs::write(&path, "example.com {\n\tfile_server\n").unwrap();
        let err = parse_file(&path).unwrap_err();
        assert!(err.source().is_none());
    }

    #[test]
    fn parse_file_translate_error_includes_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Caddyfile");
        std::fs::write(
            &path,
            "example.com {\n\t@api {\n\t\tpath /api/*\n\t}\n\treverse_proxy @api localhost:8080\n}\n",
        )
        .unwrap();

        let err = parse_file(&path).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("parsing"));
        assert!(msg.contains("named matcher"));
    }

    #[test]
    fn parse_dir_later_file_overrides_earlier_for_same_host() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("001.caddyfile"),
            "example.com {\n\treverse_proxy /api localhost:1111\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("002.caddyfile"),
            "example.com {\n\treverse_proxy /api localhost:2222\n}\n",
        )
        .unwrap();

        let table = parse_dir(dir.path()).unwrap();
        assert_eq!(table.hosts.len(), 2);
    }
}
