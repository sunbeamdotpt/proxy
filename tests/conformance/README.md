# Gateway API v1.5.1 Conformance Runner

The `run.sh` script builds the sunbeam-proxy image, deploys it into the
conformance VM, and executes the upstream Gateway API conformance suite.

## Usage

```sh
KUBECONFIG=/tmp/k3s.yaml ./scripts/conformance-run.sh
```

Run a focused subset:

```sh
./scripts/conformance-run.sh -run 'TestConformance/HTTPRouteCrossNamespace'
```

Reuse an already-built image:

```sh
SKIP_BUILD=1 ./scripts/conformance-run.sh
```

Build and run with a debug binary for faster iteration:

```sh
DEBUG_BUILD=1 ./scripts/conformance-run.sh
```



## Idempotency and Repeatability

The runner is designed to be safe to run repeatedly against the same cluster:

* `install_crds` re-applies the official CRDs (apply is idempotent).
* `cleanup_leftovers` removes stale `HTTPRoute`, `GRPCRoute`, `TLSRoute`,
  `ReferenceGrant`, and `gateway-conformance` namespace `Gateway` resources from
  previous runs so they cannot shadow the current test's routes.
* `deploy_proxy` restarts the Deployment so the freshly-built image is always
  used.
* The suite is invoked with `cleanup-base-resources=false`; the base Gateways,
  Services and Deployments are reused across runs.

To verify repeatability locally:

```sh
./scripts/conformance-idempotent.sh
```

This runs the focused conformance suite twice in a row and fails if either run
returns a non-zero exit code.
