// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Reconciler-task watchdog supervisor.
//!
//! Spawns each reconcile task on a dedicated tokio runtime and monitors
//! for panics.  Restarts tasks with exponential backoff until a crash
//! budget (≥3 panics in 60 s for the same key) is exhausted.

use anyhow::Result;
use prometheus::Gauge;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

static RUNTIME_BUSY: LazyLock<Gauge> = LazyLock::new(|| {
    let g = Gauge::new(
        "gateway_reconciler_runtime_busy_seconds",
        "Number of active reconcile tasks supervised by the watchdog",
    )
    .unwrap();
    crate::metrics::REGISTRY
        .register(Box::new(g.clone()))
        .unwrap();
    g
});

/// Key identifying a specific reconcile target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReconcileKey {
    pub namespace: String,
    pub name: String,
    pub generation: i64,
}

/// Outcome produced by the watchdog when a task exceeds its crash budget.
#[derive(Debug)]
pub enum WatchdogOutcome {
    Poisoned(ReconcileKey),
}

type TaskFactory = Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

struct TaskState {
    abort: AbortHandle,
    factory: TaskFactory,
}

/// Watchdog that owns a dedicated tokio runtime for reconciler tasks.
pub struct Watchdog {
    runtime: Runtime,
    tasks: HashMap<ReconcileKey, TaskState>,
    panic_tx: mpsc::UnboundedSender<ReconcileKey>,
    panic_rx: mpsc::UnboundedReceiver<ReconcileKey>,
    budget: HashMap<ReconcileKey, Vec<Instant>>,
    pending_restarts: Vec<(ReconcileKey, TaskFactory, Instant)>,
}

impl Watchdog {
    /// Build a new watchdog with its own dedicated runtime.
    pub fn new() -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("gateway-reconciler")
            .enable_all()
            .build()?;
        let (panic_tx, panic_rx) = mpsc::unbounded_channel();
        Ok(Self {
            runtime,
            tasks: HashMap::new(),
            panic_tx,
            panic_rx,
            budget: HashMap::new(),
            pending_restarts: Vec::new(),
        })
    }

    /// Spawn a new reconcile task supervised by the watchdog.
    pub fn spawn<F>(&mut self, key: ReconcileKey, factory: F)
    where
        F: Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'static,
    {
        self.spawn_inner(key, Box::new(factory));
    }

    fn spawn_inner(&mut self, key: ReconcileKey, factory: TaskFactory) {
        let panic_tx = self.panic_tx.clone();
        let k = key.clone();
        let f = factory();
        let inner = self.runtime.spawn(f);
        let abort = inner.abort_handle();
        self.runtime.spawn(async move {
            if let Err(e) = inner.await {
                if e.is_panic() {
                    let _ = panic_tx.send(k);
                }
            }
        });
        self.tasks.insert(key, TaskState { abort, factory });
    }

    /// Observe running tasks, process panics, and return any outcomes.
    ///
    /// Call this periodically (e.g. every reconcile tick).
    pub fn tick(&mut self) -> Vec<WatchdogOutcome> {
        let now = Instant::now();
        let mut outcomes = Vec::new();

        // Execute pending restarts whose backoff has elapsed.
        let mut i = 0;
        while i < self.pending_restarts.len() {
            if now >= self.pending_restarts[i].2 {
                let (key, factory, _) = self.pending_restarts.remove(i);
                self.spawn_inner(key, factory);
            } else {
                i += 1;
            }
        }

        // Drain panic signals.
        while let Ok(key) = self.panic_rx.try_recv() {
            let entries = self.budget.entry(key.clone()).or_default();
            entries.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
            entries.push(now);

            if entries.len() >= 3 {
                outcomes.push(WatchdogOutcome::Poisoned(key.clone()));
                self.tasks.remove(&key);
            } else if let Some(wt) = self.tasks.remove(&key) {
                let backoff =
                    Duration::from_millis(50 * (1_u64 << entries.len().saturating_sub(1)));
                self.pending_restarts.push((key, wt.factory, now + backoff));
            }
        }

        RUNTIME_BUSY.set(self.tasks.len() as f64);
        outcomes
    }

    /// Abort all running tasks.  Called on graceful shutdown.
    pub fn abort_all(&mut self) {
        for (_, state) in self.tasks.drain() {
            state.abort.abort();
        }
        self.pending_restarts.clear();
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.abort_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn restart_after_panic_within_five_ticks() {
        let mut w = Watchdog::new().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        w.spawn(
            ReconcileKey {
                namespace: "default".into(),
                name: "gw".into(),
                generation: 1,
            },
            move || {
                let c = c.clone();
                Box::pin(async move {
                    if c.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("synthetic panic");
                    }
                    std::future::pending::<()>().await;
                })
            },
        );

        // Allow the panic to propagate through the wrapper task.
        std::thread::sleep(Duration::from_millis(150));

        let mut restarted = false;
        for _ in 0..5 {
            w.tick();
            if w.tasks.len() == 1 {
                restarted = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(restarted, "task should have been restarted after panic");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn poisoned_after_three_panics() {
        let mut w = Watchdog::new().unwrap();
        w.spawn(
            ReconcileKey {
                namespace: "default".into(),
                name: "gw".into(),
                generation: 1,
            },
            || {
                Box::pin(async move {
                    panic!("always panic");
                })
            },
        );

        let mut poisoned = false;
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(80));
            let outcomes = w.tick();
            if outcomes
                .iter()
                .any(|o| matches!(o, WatchdogOutcome::Poisoned(_)))
            {
                poisoned = true;
                break;
            }
        }
        assert!(poisoned, "should be poisoned after 3 panics");
    }
}
