# Contributing to Sunbeam Proxy

We're a small team and we welcome contributions. Here's what you need to know.

## Contributor License Agreement

All contributions require a signed CLA. Read [CLA.md](CLA.md) for the full text.

**The short version:** you keep ownership of your code, but you grant Sunbeam Studios the right to license it under any terms (including commercial). This lets us offer dual licensing while keeping the project AGPL-3.0-or-later for everyone.

### How to sign

Add `Signed-off-by` to every commit:

```bash
git commit -s -m "feat(proxy): add cool thing"
```

This is enforced by a lefthook commit-msg hook. Set up lefthook:

```bash
lefthook install
```

If you forget, amend your commit:

```bash
git commit --amend -s
```

## Development Setup

```bash
# Install Rust (if you haven't)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://src.sunbeam.pt/studio/proxy.git
cd proxy
cargo build

# Run tests
cargo nextest run
# or
cargo test

# Local dev server
SUNBEAM_CONFIG=dev.toml RUST_LOG=info cargo run
```

## Making Changes

1. Fork the repo and create a branch
2. Make your changes
3. Run `cargo check`, `cargo test`, and `cargo clippy -- -D warnings`
4. Commit with conventional commit messages and `Signed-off-by`
5. Open a pull request

### Commit Messages

We use [conventional commits](https://www.conventionalcommits.org/):

```
feat(proxy): add WebSocket compression support
fix(cache): respect Vary header in cache key
docs: update configuration reference
test: add proptests for rate limiter
```

### Code Style

- `cargo fmt` for formatting
- `cargo clippy -- -D warnings` for lints
- No `unwrap()` in production paths
- `#[serde(default)]` on new config fields for backwards compatibility
- Read the file before you edit it

## Reporting Issues

Open an issue at [src.sunbeam.pt/studio/proxy/issues](https://src.sunbeam.pt/studio/proxy/issues).

## License

By contributing, you agree that your contributions will be licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later), and that you grant additional rights as described in [CLA.md](CLA.md).
