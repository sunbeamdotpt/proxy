// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy)]
pub struct ScannerVerdict {
    pub action: ScannerAction,
    pub score: f64,
    /// Why this decision was made: "model", "allowlist", etc.
    pub reason: &'static str,
}
