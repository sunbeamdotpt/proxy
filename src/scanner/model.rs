// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Scanneraction.
pub enum ScannerAction {
    /// Allow.
    Allow,
    /// Block.
    Block,
}

#[derive(Debug, Clone, Copy)]
/// Scannerverdict.
pub struct ScannerVerdict {
    /// Action.
    pub action: ScannerAction,
    /// Score.
    pub score: f64,
    /// Why this decision was made: "model", "allowlist", etc.
    pub reason: &'static str,
}
