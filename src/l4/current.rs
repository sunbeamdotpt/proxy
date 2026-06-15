// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Global handle to the currently compiled L4 configuration.
//!
//! Event-driven controllers use this to confirm that the dataplane has picked
//! up a listener before telling the conformance suite it is ready.

use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;

use crate::ir::compile::CompiledL4Config;

static CURRENT_L4_CONFIG: OnceLock<Arc<ArcSwap<CompiledL4Config>>> = OnceLock::new();

/// Install the atomic L4 config handle.
pub fn set(config: Arc<ArcSwap<CompiledL4Config>>) {
    let _ = CURRENT_L4_CONFIG.set(config);
}

/// Return the installed atomic L4 config handle, if any.
pub fn get() -> Option<Arc<ArcSwap<CompiledL4Config>>> {
    CURRENT_L4_CONFIG.get().map(Arc::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_before_set_returns_none() {
        assert!(get().is_none());
    }

    #[test]
    fn set_and_get_roundtrip() {
        let swap = Arc::new(ArcSwap::from_pointee(CompiledL4Config::default()));
        set(Arc::clone(&swap));
        let got = get().expect("handle should be installed");
        assert!(Arc::ptr_eq(&got, &swap));
    }
}
