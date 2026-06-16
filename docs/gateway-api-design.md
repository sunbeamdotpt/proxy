# Gateway API Design Document

## Copyright Sunbeam Studios 2026
## SPDX-License-Identifier: AGPL-3.0-or-later

---

## 1. Architecture Decision — Option D (Single Binary, Autonomous Fleet)

**Decision:** Adopt *Option D* — a single `sunbeam-proxy` binary that can act as either
leader (reconciler) or follower (data-plane only) depending on lease-based election.

**Rationale:**
- Operational simplicity: one container image, one Helm chart, one monitoring target.
- Horizontal scaling: every pod is capable of becoming leader; no dedicated controller
  deployment needed.
- Failure resilience: leader loss triggers automatic failover to any healthy follower
  within the lease duration.
- This avoids the operational burden of Option A (separate controller) while keeping
  the control plane decoupled from the Kubernetes API server via gossip.

---

## 2. Lease-Based Leader Election

**Decision:** Use the Kubernetes `coordination.k8s.io/v1` Lease API for leader election.

**Rationale:**
- Native to Kubernetes; no extra etcd or ZooKeeper dependency.
- Standard pattern used by `controller-runtime`, well understood by platform teams.
- ~50 LOC wiring: create a Lease object per `sunbeam-proxy` pod, heartbeat every
  `lease_duration / 3`, and watch for acquisition/loss events.
- Fallback: if the API server is unreachable, the current leader continues to serve
  until the lease expires, then followers enter "degraded steady-state" mode
  (apply last known digest, log warnings).

**Wiring sketch (pseudocode):**

```rust
let lease = CoordinationV1Lease::new(lease_name)
    .with_holder(pod_name)
    .with_duration(15s);
loop {
    if try_acquire_or_renew(&lease).await? {
        is_leader.store(true, Relaxed);
        spawn_reconciler().await;
    } else {
        is_leader.store(false, Relaxed);
        shutdown_reconciler().await;
    }
    sleep(lease_duration / 3).await;
}
```

---

## 3. Reconciler Isolation ADR

**Decision:** Run the reconciler as a task on the proxy's shared Tokio runtime,
protected by an `AbortHandle` watchdog.

**Rationale:**
- A panic in the reconcile loop must not bring down the proxy's data plane.
- A single shared runtime keeps all Kube clients on the runtime that created them,
  avoiding Tower worker/runtime-boundary issues.
- The watchdog monitors the reconcile task; if it hangs longer than `2 × tick_interval`,
  the `AbortHandle` fires and the task is restarted.
- Cluster gossip and K8s watchers share the same runtime for operational simplicity.

---

## 4. Gossip-as-Control-Plane ADR

**Decision:** Use gossip for *digest cross-validation*, NOT delta propagation.

**Rationale:**
- **Digest, not delta:** The leader broadcasts a `GatewayStateDigest` (blake3 hash of
  the canonical reconciled view). Followers compare the hash against their locally
  computed view. Mismatches trigger a full re-list from the API server.
- **Why not delta?** Delta propagation is complex (ordering, deduplication, CRDT
  merge logic). The Gateway API object model is small enough that periodic full
  reconciliation is cheap.
- **Why gossip?** It removes the Kubernetes API server from the hot path of
  configuration distribution. Followers receive digests in milliseconds rather than
  waiting for etcd watch latency.
- **Cross-validation:** If a follower's local hash mismatches the digest, it logs
  `Conflicted` and re-syncs. This catches split-brain or stale-cache scenarios.

---

## 5. Status Condition Catalog

Gateway API standard conditions:

| Condition           | Meaning                                                            |
|---------------------|--------------------------------------------------------------------|
| `Accepted`          | The resource has been accepted by the controller.                  |
| `Programmed`        | The resource has been translated into the data plane.              |
| `ResolvedRefs`      | All `parentRefs` / `backendRefs` resolved successfully.            |
| `NoMatchingParent`  | No parent Gateway matched the route's `parentRefs`.                |
| `RefNotPermitted`   | A reference crosses a namespace boundary without a `ReferenceGrant`.|
| `UnsupportedFeature`| The route uses a feature not yet implemented by sunbeam-proxy.     |

Sunbeam-specific extensions:

| Condition   | Meaning                                                                    |
|-------------|----------------------------------------------------------------------------|
| `Conflicted`| The follower's local digest mismatches the leader's digest.               |
| `Poison`    | The resource triggered a reconciler panic; marked as unhealthy.           |

---

## 6. Supported-Features List (as of 0.2.0)

- [x] GatewayClass
- [x] Gateway (core)
- [x] HTTPRoute (core)
- [x] GRPCRoute
- [x] TCPRoute / TLSRoute
- [x] Listener `hostname` matching
- [x] TLS termination (Terminate mode, certificateRefs)
- [x] TLS passthrough
- [x] BackendRef weight-based load balancing
- [x] BackendTLSPolicy
- [x] HTTP URLRewrite filter
- [x] HTTP RequestMirror filter
- [ ] GAMMA service mesh routes (future)

---

## 7. TLS Reload ADR

**Decision:** TLS certificates are loaded from two sources and refreshed dynamically:

1. **Gateway API `certificateRefs`**: the reconciler reads referenced Secrets during
   each reconcile tick and atomically swaps the listener-specific certificates in the
   `TlsRegistry`.
2. **Disk certificates** (`tls.cert_path` / `tls.key_path`): the K8s Secret/ConfigMap
   watcher writes new cert files to disk and triggers a graceful Pingora upgrade
   (`SIGQUIT`), which inherits listening sockets in the new process.

**Rationale:**
- Gateway API certs change with the reconciled view; re-listing them every tick is
  simple and correct for the Gateway API object model.
- Disk certs follow the existing Pingora graceful-upgrade path, so hot reload requires
  no extra machinery beyond the watcher.
- Existing connections use the old cert; new connections use the new cert.
