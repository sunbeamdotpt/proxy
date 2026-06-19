// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lease-based leader election for the gateway reconciler.
//!
//! Uses the Kubernetes `coordination.k8s.io/v1` Lease API.
//! Only the leader runs the full reconcile loop; followers stay in
//! data-plane mode and apply digests received via gossip.

// todo(siennathesane): this needs to be replaced with a standard leader election process over gossip
// for right now it's fine and unblocks, but this will need to be revisited.

use k8s_openapi::api::coordination::v1::Lease;
use kube::api::{Api, Patch, PatchParams};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaderState {
    Leader,
    NotLeader,
}

/// RAII token proving current leadership. `!Clone`.
pub struct LeaderToken {
    valid: Arc<AtomicBool>,
}

impl LeaderToken {
    pub fn is_leader(&self) -> bool {
        self.valid.load(Ordering::Relaxed)
    }
}

impl Drop for LeaderToken {
    fn drop(&mut self) {
        self.valid.store(false, Ordering::Relaxed);
    }
}

/// Lease-based leader election.
pub struct Election {
    state_rx: watch::Receiver<LeaderState>,
    token_valid: Arc<AtomicBool>,
    _task: tokio::task::JoinHandle<()>,
}

/// Build a `coordination.k8s.io/v1` Lease object for the given identity.
fn build_lease(
    name: &str,
    namespace: &str,
    identity: &str,
    now: k8s_openapi::jiff::Timestamp,
) -> Lease {
    Lease {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::coordination::v1::LeaseSpec {
            holder_identity: Some(identity.to_string()),
            lease_duration_seconds: Some(15),
            renew_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(
                now,
            )),
            ..Default::default()
        }),
    }
}

/// Process the result of a Lease patch and update leadership state.
fn handle_patch_result(
    result: Result<Lease, kube::Error>,
    is_leader: &mut bool,
    token_valid: &AtomicBool,
    state_tx: &watch::Sender<LeaderState>,
) {
    match result {
        Ok(_) if !*is_leader => {
            *is_leader = true;
            token_valid.store(true, Ordering::Relaxed);
            let _ = state_tx.send(LeaderState::Leader);
        }
        Ok(_) => {}
        Err(_) if *is_leader => {
            *is_leader = false;
            token_valid.store(false, Ordering::Relaxed);
            let _ = state_tx.send(LeaderState::NotLeader);
        }
        Err(_) => {}
    }
}

impl Election {
    /// Start the lease acquisition / renewal loop.
    pub fn new(client: kube::Client, namespace: String, name: String, identity: String) -> Self {
        let (state_tx, state_rx) = watch::channel(LeaderState::NotLeader);
        let token_valid = Arc::new(AtomicBool::new(false));
        let tv = token_valid.clone();
        let leases: Api<Lease> = Api::namespaced(client, &namespace);
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            let mut is_leader = false;
            loop {
                interval.tick().await;
                let now = k8s_openapi::jiff::Timestamp::now();
                let lease = build_lease(&name, &namespace, &identity, now);
                let result = leases
                    .patch(
                        &name,
                        &PatchParams::apply("sunbeam-proxy"),
                        &Patch::Apply(lease),
                    )
                    .await;
                handle_patch_result(result, &mut is_leader, &tv, &state_tx);
            }
        });
        Self {
            state_rx,
            token_valid,
            _task: task,
        }
    }

    /// Current leader state.
    pub fn state(&self) -> LeaderState {
        *self.state_rx.borrow()
    }

    /// Obtain a leader token if currently leading.
    pub fn token(&self) -> Option<LeaderToken> {
        if *self.state_rx.borrow() == LeaderState::Leader {
            self.token_valid.store(true, Ordering::Relaxed);
            Some(LeaderToken {
                valid: self.token_valid.clone(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_becomes_invalid_on_drop() {
        let valid = Arc::new(AtomicBool::new(true));
        let token = LeaderToken {
            valid: valid.clone(),
        };
        assert!(token.is_leader());
        drop(token);
        assert!(!valid.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn token_returns_none_when_not_leader() {
        let (_, rx) = watch::channel(LeaderState::NotLeader);
        let e = Election {
            state_rx: rx,
            token_valid: Arc::new(AtomicBool::new(false)),
            _task: tokio::spawn(async {}),
        };
        assert!(e.token().is_none());
    }

    #[tokio::test]
    async fn token_returns_some_when_leader_and_revokes_on_loss() {
        let (tx, rx) = watch::channel(LeaderState::Leader);
        let tv = Arc::new(AtomicBool::new(true));
        let e = Election {
            state_rx: rx,
            token_valid: tv.clone(),
            _task: tokio::spawn(async {}),
        };
        let token = e.token().expect("should be leader");
        assert!(token.is_leader());

        // Simulate lease loss
        tx.send(LeaderState::NotLeader).unwrap();
        tv.store(false, Ordering::Relaxed);
        assert!(!token.is_leader());
    }

    #[test]
    fn build_lease_populates_fields() {
        let now = k8s_openapi::jiff::Timestamp::from_second(1_700_000_000).unwrap();
        let lease = build_lease("my-lease", "default", "pod-1", now);
        let meta = lease.metadata;
        assert_eq!(meta.name.as_deref(), Some("my-lease"));
        assert_eq!(meta.namespace.as_deref(), Some("default"));
        let spec = lease.spec.unwrap();
        assert_eq!(spec.holder_identity.as_deref(), Some("pod-1"));
        assert_eq!(spec.lease_duration_seconds, Some(15));
        assert!(spec.renew_time.is_some());
    }

    #[test]
    fn handle_patch_result_transitions_to_leader_on_ok() {
        let (tx, rx) = watch::channel(LeaderState::NotLeader);
        let tv = AtomicBool::new(false);
        let mut is_leader = false;

        let lease = build_lease("l", "ns", "id", k8s_openapi::jiff::Timestamp::now());
        handle_patch_result(Ok(lease), &mut is_leader, &tv, &tx);

        assert!(is_leader);
        assert!(tv.load(Ordering::Relaxed));
        assert_eq!(*rx.borrow(), LeaderState::Leader);
    }

    #[test]
    fn handle_patch_result_stays_leader_on_repeated_ok() {
        let (tx, rx) = watch::channel(LeaderState::Leader);
        let tv = AtomicBool::new(true);
        let mut is_leader = true;

        let lease = build_lease("l", "ns", "id", k8s_openapi::jiff::Timestamp::now());
        handle_patch_result(Ok(lease), &mut is_leader, &tv, &tx);

        assert!(is_leader);
        assert!(tv.load(Ordering::Relaxed));
        assert_eq!(*rx.borrow(), LeaderState::Leader); // no change
    }

    #[test]
    fn handle_patch_result_loses_leader_on_err() {
        let (tx, rx) = watch::channel(LeaderState::Leader);
        let tv = AtomicBool::new(true);
        let mut is_leader = true;

        let err =
            kube::Error::Service(std::io::Error::new(std::io::ErrorKind::Other, "mock").into());
        handle_patch_result(Err(err), &mut is_leader, &tv, &tx);

        assert!(!is_leader);
        assert!(!tv.load(Ordering::Relaxed));
        assert_eq!(*rx.borrow(), LeaderState::NotLeader);
    }

    #[tokio::test]
    async fn election_new_spawns_task_and_state_returns_not_leader() {
        use std::future::Ready;
        use std::task::{Context, Poll};
        use tower::Service;

        struct MockSvc;
        impl Service<http::Request<kube::client::Body>> for MockSvc {
            type Response = http::Response<kube::client::Body>;
            type Error = std::io::Error;
            type Future = Ready<Result<Self::Response, Self::Error>>;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _req: http::Request<kube::client::Body>) -> Self::Future {
                std::future::ready(Ok(http::Response::new(kube::client::Body::empty())))
            }
        }

        let client = kube::Client::new(MockSvc, "default");
        let election = Election::new(client, "default".into(), "test".into(), "pod-1".into());

        // Give the background lease task time to call the mock service.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Before the background task acquires leadership, state is NotLeader.
        assert_eq!(election.state(), LeaderState::NotLeader);
        assert!(election.token().is_none());
    }

    #[test]
    fn handle_patch_result_ignores_err_when_not_leader() {
        let (tx, rx) = watch::channel(LeaderState::NotLeader);
        let tv = AtomicBool::new(false);
        let mut is_leader = false;

        let err =
            kube::Error::Service(std::io::Error::new(std::io::ErrorKind::Other, "mock").into());
        handle_patch_result(Err(err), &mut is_leader, &tv, &tx);

        assert!(!is_leader);
        assert!(!tv.load(Ordering::Relaxed));
        assert_eq!(*rx.borrow(), LeaderState::NotLeader); // no change
    }
}
