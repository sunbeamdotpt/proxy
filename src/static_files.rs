// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

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
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" | "ico" => {
            "public, max-age=86400"
        }
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

/// Try to read a file from disk. Returns None if the file doesn't exist.
async fn read_static_file(path: &Path) -> Option<StaticFile> {
    let metadata = match tokio::fs::metadata(path).await {
        Ok(m) if m.is_file() => m,
        _ => return None,
    };

    let body = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(_) => return None,
    };

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    Some(StaticFile {
        len: metadata.len(),
        body,
        content_type: content_type_for(ext),
        cache_control: cache_control_for(ext),
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
    let root = Path::new(static_root);

    // Sanitize: reject path traversal attempts.
    if path.contains("..") {
        return Ok(false);
    }

    // Strip leading slash for path joining.
    let relative = path.strip_prefix('/').unwrap_or(path);

    // try_files chain: exact → .html → /index.html
    let candidates: Vec<PathBuf> = if relative.is_empty() {
        vec![root.join("index.html")]
    } else {
        vec![
            root.join(relative),
            root.join(format!("{relative}.html")),
            root.join(format!("{relative}/index.html")),
        ]
    };

    // Find the first matching file.
    let mut file = None;
    for candidate in &candidates {
        if let Some(f) = read_static_file(candidate).await {
            file = Some(f);
            break;
        }
    }

    // Try fallback if no candidate matched.
    if file.is_none() {
        if let Some(fb) = fallback {
            file = read_static_file(&root.join(fb)).await;
        }
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
    session.write_response_body(Some(file.body.into()), true).await?;

    Ok(true)
}
