// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared backend-ref resolution logic for Gateway API routes.

use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::gateway::status::{conditions, ConditionStatus, StatusCondition};

/// Status of resolving backend references for a route.
#[derive(Clone, Debug)]
pub enum BackendResolutionStatus {
    Ok,
    RefNotPermitted(String),
    Unsupported(String),
    BackendNotFound(String),
}

/// Per-rule backend resolution result.
#[derive(Clone, Debug)]
pub struct RuleBackendResolution {
    pub ok: bool,
    pub message: String,
}

/// Backend-ref resolution for a route. `overall` drives status conditions;
/// `rules` is parallel to the route's rules and drives per-rule programming.
#[derive(Clone, Debug)]
pub struct BackendResolution {
    pub overall: BackendResolutionStatus,
    pub rules: Vec<RuleBackendResolution>,
}

impl BackendResolution {
    pub fn ok() -> Self {
        Self {
            overall: BackendResolutionStatus::Ok,
            rules: Vec::new(),
        }
    }
}

/// Build the `ResolvedRefs` and `Programmed` conditions from a backend
/// resolution result.
pub fn build_backend_resolution_conditions(
    resolution: &BackendResolution,
    accepted: bool,
    generation: i64,
) -> Vec<StatusCondition> {
    let resolved_refs = match &resolution.overall {
        BackendResolutionStatus::Ok => conditions::resolved_refs_condition(
            ConditionStatus::True,
            "ResolvedRefs",
            "All backend references resolved",
            generation,
        ),
        BackendResolutionStatus::RefNotPermitted(msg) => conditions::resolved_refs_condition(
            ConditionStatus::False,
            "RefNotPermitted",
            msg,
            generation,
        ),
        BackendResolutionStatus::Unsupported(msg) => conditions::resolved_refs_condition(
            ConditionStatus::False,
            "InvalidKind",
            msg,
            generation,
        ),
        BackendResolutionStatus::BackendNotFound(msg) => conditions::resolved_refs_condition(
            ConditionStatus::False,
            "BackendNotFound",
            msg,
            generation,
        ),
    };

    let programmed = if matches!(resolution.overall, BackendResolutionStatus::Ok) && accepted {
        conditions::programmed_condition(
            ConditionStatus::True,
            "Programmed",
            "Route programmed into proxy",
            generation,
        )
    } else {
        conditions::programmed_condition(
            ConditionStatus::False,
            "NotProgrammed",
            "Route not programmed into proxy",
            generation,
        )
    };

    vec![resolved_refs, programmed]
}

/// Abstraction over the generated backend-ref types from each route kind.
pub trait BackendRefLike {
    fn group(&self) -> Option<&str>;
    fn kind(&self) -> Option<&str>;
    fn namespace(&self) -> Option<&str>;
    fn name(&self) -> &str;
    fn port(&self) -> Option<i32> {
        None
    }
    fn weight(&self) -> Option<i32> {
        None
    }
}

/// Implement [`BackendRefLike`] for a generated backend-ref type.
#[macro_export]
macro_rules! impl_backend_ref_like {
    ($t:ty) => {
        impl $crate::gateway::reconcile::backend::BackendRefLike for $t {
            fn group(&self) -> Option<&str> {
                self.group.as_deref()
            }
            fn kind(&self) -> Option<&str> {
                self.kind.as_deref()
            }
            fn namespace(&self) -> Option<&str> {
                self.namespace.as_deref()
            }
            fn name(&self) -> &str {
                &self.name
            }
        }
    };
    ($t:ty, $port:ident, $weight:ident) => {
        impl $crate::gateway::reconcile::backend::BackendRefLike for $t {
            fn group(&self) -> Option<&str> {
                self.group.as_deref()
            }
            fn kind(&self) -> Option<&str> {
                self.kind.as_deref()
            }
            fn namespace(&self) -> Option<&str> {
                self.namespace.as_deref()
            }
            fn name(&self) -> &str {
                &self.name
            }
            fn port(&self) -> Option<i32> {
                self.$port
            }
            fn weight(&self) -> Option<i32> {
                self.$weight
            }
        }
    };
}

/// Abstraction over a route rule so backend refs can be resolved generically.
pub trait RuleLike {
    type BackendRef: BackendRefLike;
    fn backend_refs(&self) -> Option<&[Self::BackendRef]>;
}

/// Abstraction over a route CRD so backend refs can be resolved generically.
pub trait RouteLike {
    type Rule: RuleLike;
    fn rules(&self) -> Option<&[Self::Rule]>;
    fn kind() -> &'static str;
}

/// Check whether a single backend reference is permitted for `route_ns`.
pub fn check_backend_permitted<T: BackendRefLike>(
    backend: &T,
    route_ns: &str,
    route_kind: &str,
    grant_index: &GrantIndex,
) -> Result<(), BackendResolutionStatus> {
    let group = backend.group().unwrap_or("");
    let kind = backend.kind().unwrap_or("Service");
    let target_ns = backend.namespace().unwrap_or(route_ns);

    if !group.is_empty() || kind != "Service" {
        return Err(BackendResolutionStatus::Unsupported(format!(
            "backendRef group {} kind {} is not supported",
            group, kind
        )));
    }

    let permitted = grant_index.is_permitted(
        route_ns,
        "gateway.networking.k8s.io",
        route_kind,
        target_ns,
        group,
        kind,
        backend.name(),
    );

    if !permitted {
        return Err(BackendResolutionStatus::RefNotPermitted(format!(
            "cross-namespace backend reference from {} to {}/{} is not permitted",
            route_ns,
            target_ns,
            backend.name()
        )));
    }

    Ok(())
}

/// Resolve backend references for a route without validating Service existence.
pub fn resolve_backend_refs<R: RouteLike>(
    route: &R,
    route_ns: &str,
    grant_index: &GrantIndex,
) -> BackendResolution {
    let rules = match route.rules() {
        Some(r) => r,
        None => return BackendResolution::ok(),
    };

    let route_kind = R::kind();
    let mut overall = BackendResolutionStatus::Ok;
    let mut rule_results = Vec::with_capacity(rules.len());

    for rule in rules {
        let backends = match rule.backend_refs() {
            Some(b) => b,
            None => {
                rule_results.push(RuleBackendResolution {
                    ok: true,
                    message: String::new(),
                });
                continue;
            }
        };

        let mut rule_ok = true;
        let mut rule_message = String::new();
        for backend in backends {
            if let Err(status) = check_backend_permitted(backend, route_ns, route_kind, grant_index)
            {
                if matches!(overall, BackendResolutionStatus::Ok) {
                    overall = status.clone();
                }
                rule_ok = false;
                if rule_message.is_empty() {
                    rule_message = match &status {
                        BackendResolutionStatus::Unsupported(msg)
                        | BackendResolutionStatus::RefNotPermitted(msg) => msg.clone(),
                        _ => String::new(),
                    };
                }
            }
        }
        rule_results.push(RuleBackendResolution {
            ok: rule_ok,
            message: rule_message,
        });
    }

    BackendResolution {
        overall,
        rules: rule_results,
    }
}

/// Resolve backend references and validate that referenced Services exist.
pub async fn resolve_backend_refs_async<R: RouteLike>(
    client: &kube::Client,
    route: &R,
    route_ns: &str,
    grant_index: &GrantIndex,
) -> BackendResolution {
    let rules = match route.rules() {
        Some(r) => r,
        None => return BackendResolution::ok(),
    };

    let route_kind = R::kind();
    let mut overall = BackendResolutionStatus::Ok;
    let mut rule_results = Vec::with_capacity(rules.len());

    for rule in rules {
        let backends = match rule.backend_refs() {
            Some(b) => b,
            None => {
                rule_results.push(RuleBackendResolution {
                    ok: true,
                    message: String::new(),
                });
                continue;
            }
        };

        let mut rule_ok = true;
        let mut rule_message = String::new();
        for backend in backends {
            if let Err(status) = check_backend_permitted(backend, route_ns, route_kind, grant_index)
            {
                if matches!(overall, BackendResolutionStatus::Ok) {
                    overall = status.clone();
                }
                rule_ok = false;
                if rule_message.is_empty() {
                    rule_message = match &status {
                        BackendResolutionStatus::Unsupported(msg)
                        | BackendResolutionStatus::RefNotPermitted(msg) => msg.clone(),
                        _ => String::new(),
                    };
                }
                continue;
            }

            let target_ns = backend.namespace().unwrap_or(route_ns);
            let services: kube::Api<k8s_openapi::api::core::v1::Service> =
                kube::Api::namespaced(client.clone(), target_ns);
            if services.get(backend.name()).await.is_err() {
                let status = BackendResolutionStatus::BackendNotFound(format!(
                    "backend Service {}/{} not found",
                    target_ns,
                    backend.name()
                ));
                if matches!(overall, BackendResolutionStatus::Ok) {
                    overall = status.clone();
                }
                rule_ok = false;
                if rule_message.is_empty() {
                    rule_message = match &status {
                        BackendResolutionStatus::BackendNotFound(msg) => msg.clone(),
                        _ => String::new(),
                    };
                }
            }
        }
        rule_results.push(RuleBackendResolution {
            ok: rule_ok,
            message: rule_message,
        });
    }

    BackendResolution {
        overall,
        rules: rule_results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub struct TestBackend {
        group: Option<String>,
        kind: Option<String>,
        namespace: Option<String>,
        name: String,
    }

    impl BackendRefLike for TestBackend {
        fn group(&self) -> Option<&str> {
            self.group.as_deref()
        }
        fn kind(&self) -> Option<&str> {
            self.kind.as_deref()
        }
        fn namespace(&self) -> Option<&str> {
            self.namespace.as_deref()
        }
        fn name(&self) -> &str {
            &self.name
        }
    }

    impl RuleLike for () {
        type BackendRef = TestBackend;
        fn backend_refs(&self) -> Option<&[Self::BackendRef]> {
            None
        }
    }

    #[test]
    fn backend_resolution_ok_when_no_rules() {
        struct EmptyRoute;
        impl RouteLike for EmptyRoute {
            type Rule = ();
            fn rules(&self) -> Option<&[Self::Rule]> {
                None
            }
            fn kind() -> &'static str {
                "TestRoute"
            }
        }

        let grant_index = GrantIndex::new(vec![]);
        let res = resolve_backend_refs(&EmptyRoute, "default", &grant_index);
        assert!(matches!(res.overall, BackendResolutionStatus::Ok));
        assert!(res.rules.is_empty());
    }
}
