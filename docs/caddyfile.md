---
title: Caddyfile Route Source
description: Configure HTTP routes, static files, reverse proxies, and auth subrequests with Caddyfiles.
category: user-guide
order: 3
parent: README.md
tags:
  - caddyfile
  - routing
  - static-files
  - reverse-proxy
status: published
visibility: public
related:
  - configuration.md
  - gateway-api.md
---

# Caddyfile Route Source

In addition to Kubernetes Gateway API, Sunbeam can load routes from one or more Caddyfiles. This is the replacement for the legacy TOML `[[routes]]` format.

## Loading Caddyfiles

Use either a single file or a directory:

```sh
sunbeam-proxy serve --caddyfile /etc/sunbeam/Caddyfile
# or
sunbeam-proxy serve --caddyfile-dir /etc/sunbeam/caddyfiles.d
```

Environment variables are also supported:

```sh
SUNBEAM_CADDYFILE=/etc/sunbeam/Caddyfile sunbeam-proxy serve
SUNBEAM_CADDYFILE_DIR=/etc/sunbeam/caddyfiles.d sunbeam-proxy serve
```

A directory is scanned for files named exactly `Caddyfile` or ending with `.caddyfile`. Files are processed in alphabetical order; later files append hosts to the route table and override listeners with the same ID.

## Precedence

Route sources are merged with the following priority (highest first):

1. Kubernetes Gateway API
2. Caddyfile (`--caddyfile` / `--caddyfile-dir`)
3. Legacy TOML `[[routes]]` (removed — an error is raised if still present)

## Supported directives

| Directive | Supported | Notes |
|-----------|-----------|-------|
| `bind` | ✅ | Global options and per-site listener configuration. |
| `file_server` | ✅ | Static file serving; combine with `root` and `try_files`. |
| `root` | ✅ | Sets the document root for the enclosing site/block. |
| `try_files` | ✅ | Literal fallbacks only; use quoted placeholders such as `"{path}"` if needed. |
| `reverse_proxy` | ✅ | One or more upstream backends; path matcher supported. |
| `rewrite` | ✅ | `rewrite <from> <to>` inside a matcher. |
| `header` | ✅ | Set or remove response headers. |
| `request_header` | ✅ | Set or remove request headers. |
| `forward_auth` | ✅ | Auth subrequest to an upstream URL. |
| `handle` | ✅ | Group directives under a path matcher. |
| `handle_path` | ✅ | Like `handle`, but strips the matched prefix. |
| `route` | ✅ | Same translation as `handle`. |
| `tls` | ⚠️ | Parsed but ignored in this release. |
| `encode`, `templates`, `basic_auth`, etc. | ❌ | Skipped with a warning. |

## Examples

### Static site with SPA fallback

```caddyfile
example.com {
	root /var/www
	try_files "{path}" "{path}/" /index.html
	file_server
}
```

### Reverse proxy under a path prefix

```caddyfile
api.example.com {
	reverse_proxy /v1/* localhost:8080
}
```

### Headers and auth subrequest

```caddyfile
app.example.com {
	request_header X-Proxy sunbeam
	forward_auth localhost:9000
	reverse_proxy localhost:3000
}
```

### Multiple sites in one file

```caddyfile
example.com {
	file_server
}

api.example.com {
	reverse_proxy localhost:8080
}
```

## Limitations

- Named matchers (`@name`) are not supported in this release.
- `try_files` placeholders must be quoted (`"{path}"`) so the parser can distinguish them from blocks.
- TLS listener certificates should continue to be configured through Gateway API or the TOML `[tls]` section; the `tls` Caddyfile directive is parsed but has no effect.
