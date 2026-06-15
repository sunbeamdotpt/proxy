// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lightweight hook that event-driven controllers use to nudge the main
//! reconcile loop immediately after processing a resource change.

use std::sync::{Arc, OnceLock};
use tokio::sync::Notify;

static FORCE_RECONCILE: OnceLock<Arc<Notify>> = OnceLock::new();

/// Install the notify handle used by the leadership reconcile loop.
pub fn init(force: Arc<Notify>) {
    let _ = FORCE_RECONCILE.set(force);
}

/// Wake the main reconcile loop, if it has been initialized.
pub fn trigger() {
    if let Some(n) = FORCE_RECONCILE.get() {
        n.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn trigger_is_noop_when_uninitialized() {
        // The static OnceLock is shared across the test binary; this simply
        // exercises the branch where FORCE_RECONCILE has not (yet) been set.
        trigger();
    }

    #[test]
    fn init_stores_notify_handle() {
        let notify = Arc::new(Notify::new());
        init(Arc::clone(&notify));
        // If FORCE_RECONCILE was already set by another test, init is a no-op.
        // Either way the global getter should now return a handle.
        assert!(FORCE_RECONCILE.get().is_some());
    }
}
