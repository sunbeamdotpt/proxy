// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared reconciler context and generic controller runner.

use futures::StreamExt;
use kube::Client;
use kube::api::Api;
use kube::runtime::controller::{Action, Controller};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Context shared across all resource reconcilers.
#[derive(Clone)]
pub struct ReconcilerContext {
    pub client: Client,
    pub is_leader: Arc<AtomicBool>,
}

/// Start a generic kube controller for resource `R`.
///
/// The supplied `reconcile` and `error_policy` functions receive an
/// [`Arc<ReconcilerContext>`] containing the Kubernetes client and the
/// leadership flag used to gate status writeback.
pub fn run_controller<R, ReconcileFn, ReconcileFut, ErrorPolicyFn>(
    client: Client,
    is_leader: Arc<AtomicBool>,
    reconcile: ReconcileFn,
    error_policy: ErrorPolicyFn,
    resource_name: &'static str,
) -> tokio::task::JoinHandle<()>
where
    R: kube::Resource
        + Clone
        + Send
        + Sync
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + 'static,
    R::DynamicType:
        Default + Clone + Eq + std::hash::Hash + std::fmt::Debug + Unpin + Send + Sync + 'static,
    ReconcileFn: FnMut(Arc<R>, Arc<ReconcilerContext>) -> ReconcileFut + Send + Sync + 'static,
    ReconcileFut: Future<Output = Result<Action, kube::Error>> + Send + 'static,
    ErrorPolicyFn:
        Fn(Arc<R>, &kube::Error, Arc<ReconcilerContext>) -> Action + Send + Sync + 'static,
{
    let ctx = Arc::new(ReconcilerContext {
        client: client.clone(),
        is_leader,
    });
    let api = Api::<R>::all(client);
    tokio::spawn(async move {
        Controller::new(api, kube::runtime::watcher::Config::default())
            .run(reconcile, error_policy, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(_) => {}
                    Err(e) => tracing::error!("{resource_name} controller error: {e}"),
                }
            })
            .await;
    })
}
