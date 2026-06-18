---
title: Gateway API Usage
description: Configure routing with Kubernetes Gateway API CRDs.
category: user-guide
order: 1
parent: README.md
tags:
  - gateway-api
  - kubernetes
  - routing
status: published
visibility: public
related:
  - configuration.md
---

# Gateway API Usage

Sunbeam Proxy implements the Kubernetes Gateway API v1.5 control plane and data plane. Routing, TLS termination, backend policies, and L4 traffic are all configured through standard Gateway API CRDs.

## Supported resources

| Kind | API version | Notes |
|---|---|---|
| `GatewayClass` | `gateway.networking.k8s.io/v1` | Managed when `controllerName: sunbeam`; reports `supportedFeatures`. |
| `Gateway` | `gateway.networking.k8s.io/v1` | Listeners, addresses, TLS, `allowedListeners`, `infrastructure`. |
| `HTTPRoute` | `gateway.networking.k8s.io/v1` | Full reconciler + data-plane translation. |
| `GRPCRoute` | `gateway.networking.k8s.io/v1` | Full reconciler + data-plane translation. |
| `TCPRoute` | `gateway.networking.k8s.io/v1alpha2` | TCP relay to weighted backends. |
| `UDPRoute` | `gateway.networking.k8s.io/v1alpha2` | UDP relay to weighted backends. |
| `TLSRoute` | `gateway.networking.k8s.io/v1alpha2` | SNI hostname matching; terminate and passthrough modes. |
| `ReferenceGrant` | `gateway.networking.k8s.io/v1` | Cross-namespace refs for Gateway, Service, Secret, and ConfigMap. |
| `ListenerSet` | `gateway.networking.k8s.io/v1` | Additional listeners attached to a Gateway via `allowedListeners`. |
| `BackendTLSPolicy` | `gateway.networking.k8s.io/v1alpha3` | Service-targeted backend TLS validation. |

## Quick example

```yaml
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: sunbeam
spec:
  controllerName: sunbeam
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: ingress
spec:
  gatewayClassName: sunbeam
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: Same
    - name: https
      protocol: HTTPS
      port: 443
      hostname: "*.sunbeam.pt"
      tls:
        mode: Terminate
        certificateRefs:
          - name: sunbeam-tls
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: docs
  namespace: ingress
spec:
  parentRefs:
    - name: public
      sectionName: https
  hostnames:
    - "docs.sunbeam.pt"
  rules:
    - backendRefs:
        - name: docs-backend
          port: 8080
```

## Gateway listeners

Sunbeam treats every listener as a traffic edge: a protocol, a port, an optional hostname, and rules about which routes may attach.

- **Protocols:** `HTTP`, `HTTPS`, `TCP`, `UDP`, and `TLS`.
- **TLS modes:** HTTPS listeners terminate TLS by default. `TLS` listeners support `Terminate` and `Passthrough`; mixed modes on the same port are accepted when the GatewayClass advertises the `TLSRouteModeMixed` feature.
- **Hostname matching:** listeners can specify an exact or wildcard hostname. Routes can only attach when their hostnames intersect the listener's hostname.
- **Allowed routes:** each listener controls which route kinds and namespaces may attach, including namespace selectors.
- **ListenerSet:** a Gateway can delegate extra listeners to separate `ListenerSet` resources, which are merged during reconciliation.

## HTTPRoute

`HTTPRoute` is the primary resource for HTTP traffic. Each rule defines matching conditions and a sequence of actions.

### Matches

- **Path:** `Exact`, `PathPrefix`, and `RegularExpression` (regex matches are parsed by the reconciler but currently dropped by the T1 data-plane translator).
- **Method:** any standard HTTP method.
- **Headers:** `Exact`, `RegularExpression`, `Present`, and `Absent`.
- **Query parameters:** `Exact` and `RegularExpression`.

A rule can list multiple matches; they are OR'd together. Within one match, path, headers, query, and method are AND'd.

### Filters

- **URLRewrite** — rewrite the request hostname, replace the full path, or replace a matched prefix.
- **RequestHeaderModifier / ResponseHeaderModifier** — set, add, or remove headers.
- **RequestRedirect** — return an HTTP redirect with optional scheme, hostname, port, path rewrite, and status code.
- **RequestMirror** — fire a copy of the request to another backend, with optional fraction/percent.
- **CORS** — add cross-origin response headers directly in the proxy.

### Backend features

- Weighted `backendRefs` for traffic splitting.
- Per-backend request/response header modifiers.
- `BackendTLSPolicy` attachment for validating upstream TLS.
- Timeouts via `rules.timeouts.backendRequest` and `rules.timeouts.request`.
- Backend protocol hints from Service `appProtocol` (`kubernetes.io/h2c`, `kubernetes.io/ws`, `kubernetes.io/wss`, `https`, etc.).
- EndpointSlice expansion for headless Services.

## GRPCRoute

`GRPCRoute` follows the same pattern as `HTTPRoute` but speaks gRPC. Matches target a service and/or method exactly, or match a service by regular expression. Header modifiers are supported, and backends get the same EndpointSlice and `BackendTLSPolicy` treatment as HTTP routes.

## TCPRoute, UDPRoute, and TLSRoute

L4 routes are simple but useful:

- **TCPRoute** attaches to a `TCP` listener and relays bytes to weighted backends.
- **UDPRoute** attaches to a `UDP` listener and relays datagrams.
- **TLSRoute** attaches to a `TLS` listener, matches on SNI hostnames, and supports both `Terminate` and `Passthrough` modes.

Each L4 route controller is started only if its CRD is installed in the cluster, so you do not pay for what you do not use.

## TLS termination

Use `tls.mode: Terminate` on an HTTPS listener and reference a TLS Secret. Sunbeam watches the Secret and reloads the listener certificates automatically. Cross-namespace certificate refs need a `ReferenceGrant`.

## TLS passthrough

Set `tls.mode: Passthrough` on a listener and create a `TLSRoute` matching the SNI hostname. The proxy relays the raw TLS stream to the backend without terminating it.

## Backend TLS policy

```yaml
apiVersion: gateway.networking.k8s.io/v1alpha3
kind: BackendTLSPolicy
metadata:
  name: docs-backend-tls
  namespace: ingress
spec:
  targetRefs:
    - group: ""
      kind: Service
      name: docs-backend
  validation:
    hostname: docs-backend.ingress.svc.cluster.local
    caCertificateRefs:
      - group: ""
        kind: ConfigMap
        name: docs-ca
```

`BackendTLSPolicy` pins a trusted identity to a Service. When a route sends traffic to that Service, Sunbeam verifies the upstream certificate against the configured CA, hostname, and subject alternative names. If multiple policies target the same Service, the oldest one wins.

## Frontend / client-certificate validation

A Gateway can ask clients for a certificate:

```yaml
spec:
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        frontend:
          default:
            validation:
              caCertificateRefs:
                - name: client-ca
          perPort:
            - port: 443
              tls:
                validation:
                  caCertificateRefs:
                    - name: client-ca
```

Modes include `AllowValidOnly` and `AllowInsecureFallback`. Cross-namespace CA refs require a `ReferenceGrant`.

## Running the reconciler

Sunbeam pods elect a leader via a Kubernetes `Lease`. The leader reconciles Gateway API resources and broadcasts a state digest over the cluster gossip protocol. Followers apply the same view locally, so every pod programs identical routes without relying on the API server for every request.
