// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use std::path::{Path, PathBuf};

/// Hardcoded content-type map for common static file extensions.
pub fn content_type_for(ext: &str) -> &'static str {
    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Cache-control header value based on extension.
pub fn cache_control_for(ext: &str) -> &'static str {
    match ext {
        "js" | "mjs" | "css" | "woff" | "woff2" | "ttf" | "otf" | "eot" | "wasm" => {
            "public, max-age=31536000, immutable"
        }
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" | "ico" => "public, max-age=86400",
        _ => "no-cache",
    }
}

/// File read result — gathered before writing to session.
struct StaticFile {
    body: Vec<u8>,
    content_type: &'static str,
    cache_control: &'static str,
    len: u64,
}

/// Try to read a file from disk. Returns None if the file doesn't exist or if
/// it resolves outside of `root` (prevents directory traversal and symlink escapes).
async fn read_static_file(root: &Path, path: &Path) -> Option<StaticFile> {
    // Resolve symlinks and relative components. Failure to canonicalize means the
    // path does not exist or is not accessible.
    let canonical = match tokio::fs::canonicalize(path).await {
        Ok(p) => p,
        Err(_) => return None,
    };

    // Ensure the resolved path is still under the configured root. The root is
    // also canonicalized so platform-specific symlinks (e.g. /var -> /private/var)
    // do not cause false rejections.
    let root = match tokio::fs::canonicalize(root).await {
        Ok(p) => p,
        Err(_) => return None,
    };
    if !canonical.starts_with(&root) {
        return None;
    }

    let metadata = match tokio::fs::metadata(&canonical).await {
        Ok(m) if m.is_file() => m,
        _ => return None,
    };

    let body = match tokio::fs::read(&canonical).await {
        Ok(b) => b,
        Err(_) => return None,
    };

    let ext = canonical.extension().and_then(|e| e.to_str()).unwrap_or("");

    Some(StaticFile {
        len: metadata.len(),
        body,
        content_type: content_type_for(ext),
        cache_control: cache_control_for(ext),
    })
}

/// Build the list of candidate file paths to try for a request path.
fn build_candidates(root: &Path, path: &str) -> Option<Vec<PathBuf>> {
    // Sanitize: reject path traversal attempts.
    if path.contains("..") {
        return None;
    }

    // Strip leading slash for path joining.
    let relative = path.strip_prefix('/').unwrap_or(path);

    Some(if relative.is_empty() {
        vec![root.join("index.html")]
    } else {
        vec![
            root.join(relative),
            root.join(format!("{relative}.html")),
            root.join(format!("{relative}/index.html")),
        ]
    })
}

/// Try to resolve and serve a static file for the given request.
///
/// Implements a `try_files` chain:
///   1. `$uri` (exact path)
///   2. `$uri.html`
///   3. `$uri/index.html`
///   4. fallback file (e.g. `index.html` for SPA)
///
/// Returns `Ok(true)` if a response was written (caller should stop processing),
/// `Ok(false)` if no static file matched (caller should proceed to upstream).
pub async fn try_serve(
    session: &mut Session,
    static_root: &str,
    fallback: Option<&str>,
    path: &str,
    extra_headers: Vec<(String, String)>,
) -> pingora_core::Result<bool> {
    let root = match tokio::fs::canonicalize(static_root).await {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    let candidates = match build_candidates(&root, path) {
        Some(c) => c,
        None => return Ok(false),
    };

    // Find the first matching file.
    let mut file = None;
    for candidate in &candidates {
        if let Some(f) = read_static_file(&root, candidate).await {
            file = Some(f);
            break;
        }
    }

    // Try fallback if no candidate matched.
    if file.is_none()
        && let Some(fb) = fallback {
            file = read_static_file(&root, &root.join(fb)).await;
        }

    let file = match file {
        Some(f) => f,
        None => return Ok(false),
    };

    // Write the response.
    let mut resp = ResponseHeader::build(200, None)?;
    resp.insert_header("Content-Type", file.content_type)?;
    resp.insert_header("Content-Length", file.len.to_string())?;
    resp.insert_header("Cache-Control", file.cache_control)?;

    for (name, value) in extra_headers {
        resp.insert_header(name, value)?;
    }

    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(file.body.into()), true)
        .await?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_content_type_for_known_extensions() {
        assert_eq!(content_type_for("html"), "text/html; charset=utf-8");
        assert_eq!(content_type_for("css"), "text/css; charset=utf-8");
        assert_eq!(
            content_type_for("js"),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(content_type_for("png"), "image/png");
        assert_eq!(content_type_for("wasm"), "application/wasm");
    }

    #[test]
    fn test_content_type_for_unknown_extension() {
        assert_eq!(content_type_for("xyz"), "application/octet-stream");
        assert_eq!(content_type_for(""), "application/octet-stream");
        // Case-sensitive: uppercase extension is treated as unknown.
        assert_eq!(content_type_for("HTML"), "application/octet-stream");
    }

    #[test]
    fn test_cache_control_for_known_extensions() {
        assert_eq!(
            cache_control_for("js"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cache_control_for("png"), "public, max-age=86400");
        assert_eq!(cache_control_for("html"), "no-cache");
        assert_eq!(cache_control_for(""), "no-cache");
    }

    #[test]
    fn test_build_candidates_root_path() {
        let root = Path::new("/srv");
        let candidates = build_candidates(root, "/").unwrap();
        assert_eq!(candidates, vec![PathBuf::from("/srv/index.html")]);
    }

    #[test]
    fn test_build_candidates_sub_path() {
        let root = Path::new("/srv");
        let candidates = build_candidates(root, "/about").unwrap();
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/srv/about"),
                PathBuf::from("/srv/about.html"),
                PathBuf::from("/srv/about/index.html"),
            ]
        );
    }

    #[test]
    fn test_build_candidates_empty_path() {
        let root = Path::new("/srv");
        let candidates = build_candidates(root, "").unwrap();
        assert_eq!(candidates, vec![PathBuf::from("/srv/index.html")]);
    }

    #[test]
    fn test_build_candidates_rejects_traversal() {
        let root = Path::new("/srv");
        assert!(build_candidates(root, "/../etc/passwd").is_none());
        assert!(build_candidates(root, "/foo/../bar").is_none());
    }

    #[test]
    fn test_build_candidates_preserves_dot_in_name() {
        // A single dot is a valid filename character, not traversal.
        let root = Path::new("/srv");
        let candidates = build_candidates(root, "/.well-known").unwrap();
        assert_eq!(candidates[0], PathBuf::from("/srv/.well-known"));
    }

    #[tokio::test]
    async fn test_read_static_file_hits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"hello world").unwrap();

        let sf = read_static_file(dir.path(), &path).await.unwrap();
        assert_eq!(sf.body, b"hello world");
        assert_eq!(sf.content_type, "text/plain; charset=utf-8");
        assert_eq!(sf.cache_control, "no-cache");
        assert_eq!(sf.len, 11);
    }

    #[tokio::test]
    async fn test_read_static_file_html() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.html");
        std::fs::write(&path, b"<html></html>").unwrap();

        let sf = read_static_file(dir.path(), &path).await.unwrap();
        assert_eq!(sf.content_type, "text/html; charset=utf-8");
        assert_eq!(sf.cache_control, "no-cache");
    }

    #[tokio::test]
    async fn test_read_static_file_js() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.js");
        std::fs::write(&path, b"console.log(1);").unwrap();

        let sf = read_static_file(dir.path(), &path).await.unwrap();
        assert_eq!(sf.content_type, "application/javascript; charset=utf-8");
        assert_eq!(sf.cache_control, "public, max-age=31536000, immutable");
    }

    #[tokio::test]
    async fn test_read_static_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.txt");
        assert!(read_static_file(dir.path(), &path).await.is_none());
    }

    #[tokio::test]
    async fn test_read_static_file_directory() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("folder");
        std::fs::create_dir(&subdir).unwrap();
        assert!(read_static_file(dir.path(), &subdir).await.is_none());
    }

    #[tokio::test]
    async fn test_read_static_file_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("LICENSE");
        std::fs::write(&path, b"MIT").unwrap();

        let sf = read_static_file(dir.path(), &path).await.unwrap();
        assert_eq!(sf.content_type, "application/octet-stream");
        assert_eq!(sf.cache_control, "no-cache");
    }

    #[tokio::test]
    async fn test_read_static_file_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, b"secret").unwrap();
        let link = dir.path().join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&secret, &link).unwrap();
        assert!(read_static_file(dir.path(), &link).await.is_none());
    }
}
