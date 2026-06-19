// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Caddyfile configuration source.
//!
//! Parses Caddyfiles with `caddyfile-rs` and translates the supported directive
//! subset into the canonical [`crate::ir::RouteTable`].

mod parser;
mod translate;

pub use parser::{ParseError, parse_dir, parse_file};
pub use translate::{TranslateError, translate};
