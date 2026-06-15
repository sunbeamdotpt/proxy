# Gateway API v1.5.1 Conformance Runner

The `conformance.sh` script builds the sunbeam-proxy image, deploys it into the
conformance VM, and executes the upstream Gateway API conformance suite. It also
has a `coverage-diff` command for inspecting unit-test coverage of changed files.

## Usage

Run the full suite:

```sh
KUBECONFIG=/tmp/k3s.yaml ./scripts/conformance.sh run
```

Run the current feature target set (one build, one deploy):

```sh
./scripts/conformance.sh run --target-set
```

Run a focused subset by listing test short names positionally:

```sh
./scripts/conformance.sh run HTTPRouteCrossNamespace HTTPRouteHostnameIntersection
```

Run a single upstream test:

```sh
./scripts/conformance.sh run --run-test HTTPRouteCrossNamespace
```

Reuse an already-built image:

```sh
./scripts/conformance.sh run --skip-build
```

Skip the Gateway API CRD reinstall when the CRDs are already correct:

```sh
./scripts/conformance.sh run --skip-crds
```

Build and run with a debug binary for faster iteration:

```sh
./scripts/conformance.sh run --debug
```

Print the computed command without running it:

```sh
./scripts/conformance.sh run --target-set --dry-run
```

Show line coverage for Rust files changed on the current branch:

```sh
./scripts/conformance.sh coverage-diff
```

## Idempotency and Repeatability

The runner is designed to be safe to run repeatedly against the same cluster:

* `install_crds` re-applies the official CRDs (apply is idempotent). Use
  `--skip-crds` to skip this step when the CRDs are unchanged.
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
