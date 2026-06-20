---
title: "Sunbeam Constellation Mesh"
category: Standards Track
docname: draft-sunbeam-proxy-constellation-mesh-00
status: Draft
authors:
  - name: Sienna Meridian Satterwhite
    org: Sunbeam Studios
    email: sienna@sunbeam.pt
    role: Principal Engineer
date: 2026-06-20
---

# Sunbeam Constellation Mesh

## Abstract

This document specifies Sunbeam Constellation Mesh, an extension to the Sunbeam proxy that enables cross-namespace routing and forwarding for both north/south (external-to-internal and internal-to-external) and east/west (workload-to-workload) traffic. Constellation Mesh introduces hierarchical, cross-namespace views modeled as a parent-child graph; delegates packet forwarding to generic interface descriptors tracked by an interface registry; supports multiple forwarding strategies including primary-plus-shadow mirroring; and defines Constellation Mesh Routing (CMR) for multi-hop east/west forwarding across the Sunbeam peer overlay. The actual iroh peer-to-peer packet forwarding implementation is outside the scope of this document; this specification defines only the data model, lookup semantics, source-precedence merge rules, interface registry contract, Constellation Mesh Routing properties, scaling properties, and interface binding contract required by the route table.

## Document Status

This document is in **Draft** status. It has not been reviewed by the architecture review board and MUST NOT be treated as a final specification.

## Table of Contents

- [1. Introduction](#1-introduction)
  - [1.1. Requirements Language](#11-requirements-language)
  - [1.2. Terminology](#12-terminology)
  - [1.3. Goals and Non-Goals](#13-goals-and-non-goals)
  - [1.4. Scope: Standardized versus Implementation-Defined](#14-scope-standardized-versus-implementation-defined)
- [2. Architecture Overview](#2-architecture-overview)
- [3. Component Specifications](#3-component-specifications)
- [4. Data Model](#4-data-model)
- [5. View Derivation](#5-view-derivation)
- [6. Lookup Semantics](#6-lookup-semantics)
- [7. Source Precedence and Conflict Resolution](#7-source-precedence-and-conflict-resolution)
- [8. Interface Registry](#8-interface-registry)
- [9. Interface Binding](#9-interface-binding)
- [10. Forwarding Strategies](#10-forwarding-strategies)
- [11. Discovery and Fallback](#11-discovery-and-fallback)
  - [11.1. Request-Path Behavior](#111-request-path-behavior)
  - [11.2. Background Discovery Parameters](#112-background-discovery-parameters)
- [12. Constellation Mesh Routing](#12-constellation-mesh-routing)
- [13. Scaling and Complexity](#13-scaling-and-complexity)
- [14. Operational Behavior](#14-operational-behavior)
  - [14.4. Retraction Handling](#144-retraction-handling)
- [15. Compatibility](#15-compatibility)
- [16. Security Considerations](#16-security-considerations)
- [17. Deployment Considerations](#17-deployment-considerations)
- [18. References](#18-references)
  - [18.1. Normative References](#181-normative-references)
  - [18.2. Informative References](#182-informative-references)
- [Acknowledgements](#acknowledgements)
- [Author's Address](#authors-address)

---

## 1. Introduction

Sunbeam proxy currently routes north/south HTTP traffic using a host-prefix and path-based route table compiled from Kubernetes Gateway API resources and TOML configuration. Future deployments require the same proxy instance to route traffic between internal workloads (east/west) across multiple namespaces, clusters, and administrative boundaries, including nodes that run outside Kubernetes.

This document extends the existing `ir::RouteTable` with a hierarchical view model, an interface registry, an interface binding layer, and Constellation Mesh Routing. A view identifies a topological scope such as a namespace, network, cluster, or the global scope. A route entry is visible only within the views to which it is attached. When a lookup matches an east/west route, the route table returns a generic interface descriptor that the interface registry resolves to a local or remote packet-forwarding attachment point. If the selected attachment point is a remote node and no direct iroh connection is available, the Constellation Mesh Routing computes a multi-hop path through the peer overlay. The actual iroh packet forwarding implementation is outside the scope of this document.

### 1.1. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
capitals, as shown here.

### 1.2. Terminology

**North/South traffic**: Network traffic that enters the cluster from an external source or leaves the cluster toward an external destination.

**East/West traffic**: Network traffic that flows between workloads inside the same cluster, federation, or administrative boundary.

**View**: A named scope in a parent-child hierarchy that restricts route visibility. Core view types are `namespace`, `network`, `cluster`, and `global`. Additional types such as `rack` or `region` MAY be defined as extensions.

**Cross-namespace view**: A view that spans more than one Kubernetes namespace while remaining bounded by a higher-level scope such as a network or cluster.

**Interface descriptor**: An opaque URI that names a packet-forwarding attachment point. The route table treats the descriptor as opaque; the interface registry resolves it to a concrete local or remote interface.

**Interface registry**: A component that tracks registered interface kinds, local interfaces bound by the proxy, and remote interfaces advertised by peer nodes. The registry selects the best available interface for a given descriptor.

**Forwarding strategy**: A decision attached to a compiled plan that selects how traffic is forwarded. Values include `NorthSouth`, `EastWest`, and `Mirror`.

**Route table**: The in-memory data structure produced by the Sunbeam `RouteManager` and consumed by the proxy during request filtering.

**Compiled route table**: The versioned, atomically-swapped result of compiling one or more route tables, as described in the existing architecture invariants.

**Config source**: A provider of route table input. Core sources are Kubernetes Gateway API, Envoy xDS, the gossip subsystem, and TOML configuration.

**Gossip announcement**: A typed message propagated by the gossip subsystem inside a common envelope. Announcements advertise views, interfaces, backend targets, parent links, and link-state routing information.

**Constellation Mesh Routing (CMR)**: The algorithm that computes a multi-hop path through the Sunbeam peer overlay when a direct iroh connection from the source node to the destination node is unavailable or undesirable.

### 1.3. Goals and Non-Goals

**Goals**:

- Define a route table data model that supports both north/south and east/west routes.
- Introduce hierarchical, cross-namespace views without breaking the existing host/path lookup path.
- Specify how the route table binds a matched route to a generic interface descriptor.
- Define an interface registry that tracks local and remote interfaces and selects the best available attachment point.
- Define Constellation Mesh Routing for multi-hop east/west forwarding across a large peer overlay.
- Preserve the invariant that the proxy performs a single route lookup per request.
- Define precedence and conflict-resolution rules across multiple config sources.
- Specify how the active view is derived from request metadata.
- Describe scaling properties and data-structure choices for thousands of nodes and hundreds of thousands of routes.

**Non-Goals**:

- The implementation details of iroh peer-to-peer packet forwarding, QUIC stream management, and connection lifecycle.
- Replacement of the Gateway API reconciler, xDS client, or TOML parser.
- Runtime creation, authentication, or teardown of iroh endpoints.
- Kubernetes-specific CRD schemas; this specification is intended to be portable to non-Kubernetes nodes.

### 1.4. Scope: Standardized versus Implementation-Defined

This specification standardizes the contracts and behaviors that multiple Sunbeam implementations must share in order to interoperate. It intentionally leaves operational tuning, internal algorithms, and platform-specific details to implementations.

**Standardized (normative)**:

- View hierarchy semantics, core view types (`namespace`, `network`, `cluster`, `global`), and parent-child visibility rules.
- View derivation precedence: mTLS identity (e.g., SPIFFE) is primary; connection-local metadata is secondary; a configured default view is the final fallback.
- Interface descriptor URI scheme (`sun:proxy:<region>:<cluster>:interface/<kind>/<id>`).
- Interface registry API contract: registration, local attachment, remote advertisement, selection, and TTL/LRU eviction semantics.
- Config source precedence order: Gateway API > xDS > gossip > TOML.
- Conflict resolution rules for overlapping routes, views, and interfaces.
- Forwarding strategy names and semantics (`NorthSouth`, `EastWest`, `Mirror`).
- Lookup pipeline invariant: one route lookup per request, producing a `CompiledPlan` that includes the selected strategy and interface descriptor.
- Constellation Mesh Routing hierarchy (cluster/region/global), gateway election invariants, LSA flooding semantics, sequence-number ordering, and next-hop computation rules.
- Gossip announcement envelope: a typed binary payload inside a versioned envelope with source NodeId and timestamp. The exact serialization format (e.g., rkyv, protobuf, CBOR) is implementation-defined, but the envelope fields and payload type discriminant MUST be preserved.
- Partial route-table semantics: a node MUST carry routes for its own views, ancestor views, and explicitly configured sibling views.

**Implementation-defined**:

- The concrete catalog of interface kinds and any per-kind syntax beyond the descriptor URI scheme.
- The exact capability-score formula for gateway election, including weights and override knobs.
- The numeric bound on shadow copies for the `Mirror` strategy and the duplicate-suppression algorithm.
- The default values for snapshot/delta log sizing, gossip backoff, and cache TTL, unless explicitly required by the standard sections above.
- Regional view-cache node selection, placement, and on-demand query protocol details.
- Additional CMR link-cost components beyond latency and how they are configured.
- Concrete data structures, locking strategies, and memory layouts used by the route table, registry, and CMR databases.
- Kubernetes CRD schemas and non-Kubernetes config source formats.
- All iroh packet forwarding concerns, including connection setup, authentication, encapsulation, and teardown.

## 2. Architecture Overview

The existing proxy pipeline performs one lookup in `request_filter` and stores the resulting `CompiledPlan` in the request context. The extended pipeline preserves this invariant but allows the lookup to consider an additional view dimension, consult the interface registry, and rely on Constellation Mesh Routing for multi-hop paths.

```text
┌─────────────────────────────────────────────────────────────────────┐
│                           Config sources                            │
│  Gateway API  │  Envoy xDS  │  Gossip (views + availability)  │  TOML  │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                        ┌────────────────────┐
                        │    RouteManager    │
                        │  merge + compile   │
                        └────────────────────┘
                                   │
                                   ▼
        ┌─────────────────┐     ┌────────────────────┐
        │ Interface       │────▶│ CompiledRouteTable │
        │ Registry        │     │   (versioned swap) │
        │ Constellation   │     └────────────────────┘
        │ Mesh Router     │
        └─────────────────┘              │
                 │                       ▼
                 │            ┌──────────────────┐
                 │            │  View resolver   │
                 │            │ (request → view) │
                 │            └──────────────────┘
                 │                       │
                 ▼                       ▼
        ┌─────────────────┐     ┌──────────────────┐
        │   Local/remote  │◀────│   Proxy lookup   │
        │   interface +   │     │(host/path/view)  │
        │   next-hop      │     └──────────────────┘
        └─────────────────┘              │
                                           ▼
                                ┌────────────────────┐
                                │   CompiledPlan     │
                                │ (strategy + iface  │
                                │  + next-hop)       │
                                └────────────────────┘
                                           │
                                           ▼
                                ┌────────────────────┐
                                │   Forwarding layer │
                                │    (out of scope)  │
                                └────────────────────┘
```

The proxy receives a request and determines the active view from request metadata. The compiled route table returns a plan that includes the matched route, the selected forwarding strategy, and the interface descriptor selected by the view. The interface registry resolves the descriptor to a concrete local or remote interface. If the interface is remote, the Constellation Mesh Routing computes the next hop toward the destination node. The forwarding layer consumes the resolved interface, next-hop NodeId, and strategy.

## 3. Component Specifications

### 3.1. View Hierarchy

**Responsibility**: Represent the nested scopes within which routes are visible.

**Interface**: Exposed to the route compiler and to lookup code as a parent-child graph of view references. Each view declares an optional parent, forming a forest rooted at `global`.

**State**: Immutable after compilation. Each compiled table contains the complete set of views it knows about, including authoritative views from Gateway API and xDS and ephemeral views from gossip.

**Failure Modes**: A request with a view not present in the table MUST enter discovery ([Section 11](#11-discovery-and-fallback)) before falling back or rejecting.

### 3.2. Config Source Merger

**Responsibility**: Merge route entries and view definitions from Gateway API, Envoy xDS, gossip, and TOML according to a fixed precedence order.

**Interface**: `merge(sources: [Source]) -> UncompiledRouteTable`.

**State**: Stateless; operates on snapshots provided by each source.

**Failure Modes**: A source that fails to produce a snapshot MUST NOT block compilation if a higher-precedence source provides the same data. A source that fails to produce any required data SHOULD be logged and skipped.

### 3.3. Route Table Compiler

**Responsibility**: Merge per-source route tables, attach each route to one or more views, resolve conflicts, validate interface descriptor syntax and kind registration against the interface registry, and produce a `CompiledRouteTable`. The compiler MUST support incremental updates for the affected view subgraphs rather than full recompilation on every change.

The compiler validates that every interface descriptor uses a registered kind and conforms to the kind's schema. It does NOT require the interface to be currently available in the registry.

**Interface**: Reuses the existing `RouteManager` compile pipeline, extended with view metadata, strategy selection, and interface registry validation.

**State**: Maintains versioned compiled tables as before. In addition, it maintains a delta log and periodic snapshots as described in [Section 13](#13-scaling-and-complexity).

**Failure Modes**: A compilation that contains syntactically invalid interface descriptors or descriptors whose kind is not registered MUST fail atomically without swapping the active table when the source is static (Gateway API, xDS, or TOML). A compilation that contains unresolved views from static sources MUST also fail atomically. Routes from dynamic sources (gossip) that reference missing views, that contain syntactically invalid interface descriptors, or that reference an unregistered interface kind MUST be skipped rather than causing compilation failure.

### 3.4. Proxy Lookup

**Responsibility**: Compute the active view for each request and perform a single lookup against the compiled route table.

**Interface**: `CompiledRouteTable::lookup(host, path, view) -> Option<CompiledPlan>`.

**State**: Stateless; reads the current compiled table from the `ArcSwap`.

**Failure Modes**: If view derivation fails, the proxy MUST treat the request as global north/south traffic.

### 3.5. View Resolver

**Responsibility**: Derive the active view from request metadata, primarily from the mTLS identity (e.g., SPIFFE) and secondarily from connection-local metadata.

**Interface**: `resolve_view(request_metadata) -> ViewRef`.

**State**: Caches derived views per connection. The cache is invalidated on connection close, SVID rotation, explicit invalidation, or a 5-minute TTL.

**Failure Modes**: If no identity or connection metadata can be mapped to a view, the resolver returns the `global` view.

### 3.6. Interface Registry

**Responsibility**: Track registered interface kinds, local interfaces bound by the proxy, and remote interfaces advertised by peer nodes; select the best available interface for a descriptor.

**Interface**:
- `register_kind(kind: InterfaceKind, schema: KindSchema) -> Result<()>`
- `register_local(descriptor: InterfaceDescriptor, attachment: LocalAttachment) -> Result<()>`
- `announce_remote(descriptor: InterfaceDescriptor, node: NodeId, metadata: ReachabilityMetadata, ttl: Duration)`
- `resolve(descriptor: InterfaceDescriptor) -> Option<ResolvedInterface>`

**State**: In-memory registry updated from static config, local binding events, and gossip announcements. Memory is bounded by TTL expiry, LRU eviction, and scope-based eviction for remote entries.

**Failure Modes**: If a descriptor cannot be resolved to any available interface, the registry returns `None` and the proxy MUST fall back according to [Section 11](#11-discovery-and-fallback).

### 3.7. Constellation Mesh Router

**Responsibility**: Maintain a hierarchical topology database, compute next-hop routes to remote nodes, and provide a next-hop NodeId to the forwarding layer.

**Interface**:
- `update_topology(lsa: LinkStateAdvertisement)`
- `compute_next_hop(destination: NodeId) -> Option<NodeId>`
- `select_gateways() -> Vec<NodeId>`

**State**: Link-state databases for the local cluster and region, plus a global forwarding table built from summarized remote routes.

**Failure Modes**: If no path exists to the destination, the Constellation Mesh Router returns `None` and the proxy MUST fall back according to [Section 11](#11-discovery-and-fallback).

## 4. Data Model

The existing route table contains routes matched by host prefix and path prefix. This document extends the model with views, forwarding strategies, interface descriptors, registry entries, and Constellation Mesh Routing state.

### 4.1. View

A view is identified by a type and a name. The core view types are `namespace`, `network`, `cluster`, and `global`. Additional types MAY be registered as extensions. Each view MAY declare a parent, forming a directed acyclic graph rooted at `global`.

If a config source or gossip announcement introduces a parent link that would create a cycle, the implementation MUST break the cycle by ignoring the new edge. When multiple edges are candidates for removal, the edge from the lower-precedence source MUST be ignored; if the sources have equal precedence, the edge with the lexically larger child-parent identifier pair MUST be ignored.

```rust
enum ViewType {
    Namespace,
    Network,
    Cluster,
    Global,
    // Extensions: Rack, Region, ...
}

struct View {
    view_type: ViewType,
    name: String,
    parent: Option<ViewRef>,
}
```

### 4.2. Route Entry Extension

Each route entry MAY contain an optional list of views and an optional forwarding strategy. When the view list is absent, the route is visible only in the global north/south table.

```rust
struct RouteEntry {
    // existing host/path/upstream/cache/auth fields
    views: Vec<ViewRef>,
    strategy: Option<ForwardingStrategy>,
    interface: Option<InterfaceDescriptor>,
}
```

### 4.3. Interface Descriptor

An interface descriptor is a URI of the form `sun:proxy:<region>:<cluster>:interface/<kind>/<id>`. The route table treats the descriptor as opaque except for syntax validation and kind registration. The `<region>` and `<cluster>` segments identify the administrative location; `<kind>` identifies the implementation family (e.g., `iroh`, `eth`); `<id>` is the implementation-specific identifier.

**Character set and escaping**:

- `<region>`, `<cluster>`, and `<kind>` MUST consist only of lowercase ASCII alphanumeric characters and hyphens (`[a-z0-9-]+`).
- The literal `/` after `interface` and between `<kind>` and `<id>` is a path separator and MUST NOT appear unescaped inside `<kind>` or `<id>`.
- `<id>` MAY contain any UTF-8 data but MUST percent-encode the following characters when they occur: `/` (`%2F`), `%` (`%25`), `:` (`%3A`), `?` (`%3F`), `#` (`%23`), and any non-printable ASCII control character.
- Implementations MUST reject descriptors that contain unescaped reserved characters or that use characters outside the allowed set for `<region>`, `<cluster>`, or `<kind>`.

This descriptor format is defined by this specification and is not required to be parsed as a generic hierarchical URI. Implementations MUST validate it according to the structure and character rules in this section.

```rust
struct InterfaceDescriptor(String); // sun:proxy:... URI
```

### 4.4. Interface Kind

Each interface kind registers a schema that defines the expected shape of the `<id>` segment and any required metadata fields. Kinds are code-defined via a Rust trait or enum.

```rust
struct InterfaceKind {
    name: String,
    schema: KindSchema,
}
```

### 4.5. Local Attachment

A local attachment represents an interface that is bound by the local proxy instance and can be used directly for forwarding. Local interfaces are discovered dynamically.

```rust
struct LocalAttachment {
    descriptor: InterfaceDescriptor,
    state: AttachmentState, // Up, Down, Draining
    since: Instant,
}
```

### 4.6. Remote Entry

A remote entry represents an interface advertised by a peer node. It includes reachability metadata used for selection.

```rust
struct RemoteEntry {
    descriptor: InterfaceDescriptor,
    node: NodeId,
    latency_ms: Option<u32>,
    hops: Option<u32>,
    health: HealthState,
    expires_at: Instant,
}
```

### 4.7. Reachability Metadata

Remote entries carry reachability metadata used to compute a composite cost:

```rust
struct ReachabilityMetadata {
    latency_ms: u32,
    hops: u32,
    health: HealthState, // Healthy, Degraded, Unhealthy
}
```

The composite cost is computed as:

```
cost = (latency_ms + hops × base_hop_penalty_ms) × health_multiplier
```

where `base_hop_penalty_ms` is a configurable constant and `health_multiplier` is `1.0` for `Healthy`, `2.0` for `Degraded`, and infinity for `Unhealthy` (causing the entry to be ignored).

### 4.8. Resolved Interface

The result of registry resolution identifies whether the selected interface is local or remote.

```rust
enum InterfaceLocation {
    Local,
    Remote { node: NodeId },
}

struct ResolvedInterface {
    descriptor: InterfaceDescriptor,
    kind: InterfaceKind,
    location: InterfaceLocation,
}
```

### 4.9. Compiled Plan Extension

The `CompiledPlan` returned by the lookup MUST include the selected forwarding strategy, resolved interface, next-hop NodeId (if remote), and view reference so that later proxy phases can pass them to the forwarding layer.

```rust
struct CompiledPlan {
    // existing route fields
    strategy: ForwardingStrategy,
    resolved_interface: ResolvedInterface,
    next_hop: Option<NodeId>,
    view: Option<ViewRef>,
}
```

### 4.10. Forwarding Strategy

```rust
enum ForwardingStrategy {
    NorthSouth,
    EastWest,
    Mirror { primary: Box<ForwardingStrategy>, shadow: Box<ForwardingStrategy> },
}
```

### 4.11. Gossip Envelope

Gossip announcements are encoded as a typed binary payload and wrapped in a common envelope. rkyv is the recommended implementation encoding, but any serialization format that preserves the envelope fields and payload type discriminant MAY be used:

```rust
struct GossipEnvelope {
    node_id: NodeId,
    timestamp: u64, // milliseconds since Unix epoch
    ttl_seconds: u32,
    payload: GossipPayload,
}

enum GossipPayload {
    ViewAnnouncement(ViewAnnouncement),
    InterfaceAnnouncement(InterfaceAnnouncement),
    TargetAnnouncement(TargetAnnouncement),
    ViewGraphFragment(ViewGraphFragment),
    Retraction(Retraction),
    LinkStateAdvertisement(LinkStateAdvertisement),
}
```

### 4.12. Link-State Advertisement

A Link-State Advertisement (LSA) announces a node's local links and their metrics. LSAs are flooded within a cluster or region and summarized at region boundaries.

```rust
struct LinkStateAdvertisement {
    origin: NodeId,
    area: AreaId, // cluster or region
    origin_epoch: u64, // boot/session identifier for this origin
    sequence: u64,
    links: Vec<Link>,
}

struct Link {
    neighbor: NodeId,
    metric: LinkMetric, // latency_ms, cost
}
```

## 5. View Derivation

The active view for a request is derived primarily from the client's mTLS identity and secondarily from connection-local metadata.

### 5.1. mTLS Identity

When a client presents a valid X.509 certificate or SVID, the view resolver extracts an identity and maps it to a view. The exact mapping from certificate fields or SPIFFE path components to views is implementation-defined. For example, a SPIFFE ID of the form `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>` MAY map to a `namespace` view named `<namespace>` within the `cluster` view derived from the trust domain. Implementations MUST document the identity-to-view mapping they support.

### 5.2. Connection-Local Metadata

If no mTLS identity is available, the view resolver inspects connection-local metadata. Examples include the local listener name, the inbound tunnel identifier, or an annotation attached by the iroh endpoint. This metadata maps to a `network` or `cluster` view.

### 5.3. Fallback to Global

If neither identity nor connection metadata resolves to a view, the request is treated as `global` north/south traffic.

## 6. Lookup Semantics

Lookup proceeds in three steps:

1. Derive the active view from the request.
2. If the active view is not in the compiled table, enter discovery ([Section 11](#11-discovery-and-fallback)).
3. Search the compiled table for the most specific host/path match within the active view.

When a route exists in multiple views along the same ancestry chain, the lookup MUST prefer the route attached to the most specific view (the view closest to the leaf in the parent-child graph).

If no view-specific route matches, the proxy SHOULD fall back to the global north/south table. This fallback preserves backward compatibility with existing routes that do not declare views.

## 7. Source Precedence and Conflict Resolution

### 7.1. Source Precedence

Config sources are merged in the following precedence order, from highest to lowest:

1. Kubernetes Gateway API
2. Envoy xDS
3. Gossip
4. TOML

TOML has the lowest precedence because this design targets networked deployments where declarative APIs and dynamic control planes are authoritative.

### 7.2. View Authority

Gateway API and Envoy xDS define the authoritative view hierarchy. Gossip MAY add ephemeral views and announce node participation in existing views, but it MUST NOT override a parent link declared by a higher-precedence source.

### 7.3. Conflict Resolution

A conflict occurs when two sources define route entries with overlapping match keys within the same or related views. Conflicts MUST be resolved deterministically in the following order:

1. More specific view wins.
2. Higher-precedence source wins.
3. Older resource creation timestamp wins.
4. Lexical sort of a source-neutral identifier wins. The identifier MUST be derived from the source record in a portable way (e.g., a deterministic hash of the source name, kind, and origin). Implementations MUST NOT use Kubernetes-specific fields such as namespace/name as the final tiebreaker.

This approach aligns with Gateway API conflict-resolution guidance where it is applicable, while remaining portable to non-Kubernetes nodes.

## 8. Interface Registry

### 8.1. Registry Responsibilities

The interface registry has three responsibilities:

1. **Kind registration**: Validate that interface descriptors use a known kind and conform to the kind's schema.
2. **Local attachment tracking**: Record interfaces that are bound by the local proxy instance and their current state.
3. **Remote interface tracking**: Record interfaces advertised by peer nodes via gossip, including reachability metadata.

### 8.2. Registry Population

The registry is populated from three sources:

1. **Static configuration**: TOML and Gateway API resources declare interface kinds and local attachment points.
2. **Local binding events**: The proxy registers an interface when it successfully binds a local attachment point. Local interfaces are discovered dynamically.
3. **Gossip announcements**: Peer nodes announce their interfaces, which the registry stores as remote entries.

### 8.3. Registry Lookup and Selection

The registry resolves an interface descriptor to a concrete interface. Resolution follows these rules:

1. If a local attachment exists for the descriptor and is in the `Up` state, the local interface is preferred by default.
2. Otherwise, if healthy remote entries exist for the descriptor, the registry selects the entry with the lowest composite cost, computed from latency, hop count, and health.
3. If no healthy local or remote interface exists, the registry returns `None`.

Implementations MAY override the local-preference rule with a configurable cost threshold. For example, a remote interface MAY be selected when its composite cost is lower than the local interface's cost by more than the configured threshold. The default behavior MUST prefer local interfaces.

### 8.4. Registry and Route Table Interaction

During compilation, the route table compiler validates that every referenced interface descriptor uses a registered kind and satisfies the kind's syntax rules. It does NOT require the interface to be currently available.

During lookup, the proxy consults the registry to resolve the descriptor selected by the route table. If the registry returns a remote interface, the proxy consults the Constellation Mesh Router for the next hop. If the registry returns `None`, the proxy enters the discovery and fallback chain.

## 9. Interface Binding

Every matched route MUST resolve to exactly one interface descriptor. Resolution follows these rules:

1. If the route entry has an explicit `interface`, that descriptor is used.
2. Otherwise, if the matched view has a default interface descriptor, that descriptor is used.
3. Otherwise, if the strategy is `NorthSouth`, the route uses the existing upstream interface.
4. Otherwise, compilation MUST fail because the interface cannot be determined.

An explicit `interface` on a route overrides any strategy-specific default. For example, a route with `strategy: NorthSouth` and an explicit `interface` descriptor uses the explicit descriptor for binding, while still forwarding to the configured upstream unless the descriptor's kind changes that behavior.

The proxy MUST pass the descriptor to the interface registry. It MUST NOT attempt to interpret the descriptor beyond equality comparison, syntax validation, kind registration, and logging.

## 10. Forwarding Strategies

### 10.1. NorthSouth

Use the conventional upstream backend. The interface descriptor, if present, identifies a local network attachment point but the request is forwarded to the configured upstream.

### 10.2. EastWest

Use the interface descriptor to select a local or remote forwarding attachment point for peer-to-peer delivery. The interface registry resolves the descriptor; the Constellation Mesh Router computes the next hop for remote interfaces; the forwarding layer maps the resolved interface and next hop to an iroh endpoint or other implementation.

### 10.3. Mirror

The primary strategy handles the request normally and produces the client response. The shadow strategy is executed asynchronously and its result is used only for observability or cache warming. The shadow MUST NOT block or affect the response to the client.

**Compilation rules**:

1. The primary strategy MUST be fully resolvable against the node’s partial route table; otherwise compilation MUST fail.
2. The shadow strategy is best-effort. If the shadow references a view or interface that is not present in the node’s partial table, compilation MUST NOT fail; the shadow is marked as unresolved and skipped at runtime.
3. A `Mirror` route MUST NOT be nested: the primary and shadow strategies MUST be `NorthSouth` or `EastWest`, not another `Mirror`.

**Runtime limits**:

1. Each shadow request is bounded by a per-request timeout.
2. Shadow concurrency is controlled by a per-node limit shared across all `Mirror` routes. If the limit is exhausted, additional shadows are dropped and counted in metrics.
3. Duplicate suppression is implementation-defined but MUST prevent the same request body from being shadowed more than once.

Mirror shadow execution SHOULD emit a structured trace event containing the request ID, shadow strategy, latency, and outcome. It SHOULD also update metrics for shadow attempts, successes, failures, and latency.

**Note**: Because the shadow is executed asynchronously, the request body stream MUST be available to both the primary and the shadow. Implementations MUST buffer or tee the body as needed, subject to the same size limits and timeouts as the primary request.

## 11. Discovery and Fallback

When a request's derived view is not present in the compiled table, or when the interface registry cannot resolve the selected descriptor, the proxy attempts to discover the missing state and falls back through a chain of wider-scoped tables.

### 11.1. Request-Path Behavior

Discovery MUST be asynchronous with respect to the request hot path. The proxy MUST NOT block a request while waiting for a gossip response. The recommended behavior is:

1. Issue a background discovery query for the missing view or interface.
2. Immediately attempt the fallback chain:
   1. Search the global north/south table for a matching route.
   2. If no global route matches, walk up the parent chain from the derived view to the nearest known ancestor and repeat the lookup.
   3. If no ancestor route matches, reject the request with 404.
3. If the background discovery query returns a result before the response headers are sent to the client, the implementation MAY retry the lookup using the newly discovered state, provided the total latency budget for the request is not exceeded.

Implementations MAY offer a synchronous discovery mode for specific deployments, but the default synchronous timeout MUST NOT exceed 5ms and MUST fall back to the chain above if discovery does not succeed within that budget.

### 11.2. Background Discovery Parameters

Background discovery queries use bounded exponential backoff when retrying unanswered queries:

- Initial delay: 50ms
- Backoff multiplier: 2
- Maximum delay: 500ms
- Retry count: 3
- Jitter: ±25%

## 12. Constellation Mesh Routing

### 12.1. Overview

Constellation Mesh Routing computes multi-hop paths through the Sunbeam peer overlay when a direct iroh connection from the source node to the destination node is unavailable or would exceed per-node connection limits. It is a hierarchical link-state protocol with summarization at region boundaries. CMR provides indirect paths for cross-cluster and cross-region destinations; it does not provide indirect paths for destinations in the same cluster.

### 12.2. Hierarchy

The overlay is organized into three levels:

1. **Cluster**: A set of nodes that form a full mesh of iroh connections. Clusters are sized in the low hundreds of nodes to respect per-node connection limits.
2. **Region**: A set of clusters. Each cluster elects two gateways that maintain iroh connections to gateways of other clusters in the same region.
3. **Global**: A set of regions. Each region elects one or more regional gateways that maintain iroh connections to regional gateways of other regions.

### 12.3. Gateway Election

Each cluster elects up to two gateways, or one gateway per available node when the cluster has fewer than two nodes. The election uses a capability score composed of static and dynamic factors such as uptime, bandwidth, and CPU/memory headroom. If all nodes are homogeneous, the capability score is expected to be equal, and the tie is broken by deterministic node ID ordering. Operators MAY override the election by designating candidate nodes or adjusting score weights.

Regional gateways are elected from cluster gateways using the same capability-score mechanism.

### 12.4. Link-State Databases

Each node maintains:

1. A **cluster link-state database** containing all nodes and links in its cluster.
2. A **regional link-state database** containing all cluster gateways and inter-cluster links in its region.
3. A **global forwarding table** containing summarized routes to remote regions, received from regional gateways.

### 12.5. Flooding and LSAs

Link-state advertisements are flooded at each level:

1. **Cluster LSAs** are flooded to all nodes in the cluster.
2. **Regional LSAs** are flooded to all cluster gateways in the region.
3. **Global summaries** are exchanged between regional gateways and redistributed into regions.

LSAs carry a monotonically increasing sequence number and an `origin_epoch`. A node identifies the authoritative state for an origin by the tuple `(origin, origin_epoch)`. A node MUST ignore an LSA when:

1. Its `origin_epoch` is less than the highest `origin_epoch` seen from that origin, or
2. Its `origin_epoch` equals the highest seen and its `sequence` is less than or equal to the newest LSA received for that epoch.

When a node receives an LSA with a higher `origin_epoch` than previously seen from that origin, it MUST discard all older LSAs from that origin and accept the new epoch's sequence starting from the initial value. A node MUST change its `origin_epoch` after restart or after any event that invalidates its previously advertised sequence state.

The `origin_epoch` for a given origin MUST be monotonically increasing across restarts. An origin MUST NOT reuse an epoch value that has already been advertised. Recommended implementation strategies include a persistent per-origin counter incremented on every restart, or a hybrid of a high-resolution boot timestamp and a persistent sequence number. Because the sequence number space is a `u64`, wraparound is not expected in practice; if it occurs, the origin MUST bump its `origin_epoch` and begin a new sequence.

Nodes recompute forwarding tables when LSAs change their link-state database. Implementations MAY batch or coalesce LSA-driven recomputation within a short bounded window (e.g., 10 milliseconds) to avoid redundant computation during high churn.

### 12.6. Route Computation

Each node runs Dijkstra's algorithm on its cluster link-state database in the background to compute shortest paths to all cluster nodes. Cluster gateways additionally run Dijkstra on the regional link-state database in the background to compute shortest paths to all regional gateways and, through them, to all clusters in the region.

Regional gateways run Dijkstra on the global topology of regional gateways in the background to compute inter-region paths. They produce summaries that describe the cost to reach each destination region and advertise them within their region.

The output of each background computation is a precomputed forwarding table. Packet forwarding performs an O(1) lookup in this table to determine the next-hop NodeId; it does not run Dijkstra on the request path.

### 12.7. Packet Forwarding

When the interface registry resolves to a remote interface at node D, the Constellation Mesh Router computes the next hop toward D:

1. If D is in the same cluster, the next hop is D directly.
2. If D is in the same region but a different cluster, the next hop is the local cluster gateway on the shortest path to D's cluster.
3. If D is in a different region, the next hop is the local cluster gateway on the shortest path to the regional gateway for D's region.

The forwarding layer receives the next-hop NodeId and establishes or reuses an iroh connection to that node. The actual iroh forwarding is outside the scope of this document.

CMR does not provide intra-cluster indirect paths. If D is in the same cluster and the direct connection to D is unavailable, the proxy MUST fall back to the discovery and failure chain in [Section 11](#11-discovery-and-fallback).

### 12.8. Path Quality Metrics

The default link metric is measured latency in milliseconds. Operators MAY configure additional cost components. The Constellation Mesh Router minimizes the sum of link metrics along the path.

### 12.9. Convergence and Failover

When a link or node fails, the failure is detected through iroh connection events and flooded as an updated LSA. Nodes recompute routes upon receiving an LSA that changes their link-state database. Convergence time within a cluster or region is expected to be sub-second; global convergence is expected to be on the order of seconds.

## 13. Scaling and Complexity

### 13.1. Target Scale

The design targets deployments of thousands of nodes, hundreds of thousands of routes per proxy, and more than one hundred views per node. At this scale, full replication of every route to every node is infeasible.

### 13.2. Partial Route Tables

Each node carries a partial route table containing:

1. Routes for views the node participates in.
2. Routes for ancestor views of those views.
3. Routes for sibling views that are explicitly configured or discovered.

Routes for unknown views are loaded on demand via gossip queries to peers or regional cache nodes.

### 13.3. Shared Radix Tree

The compiled route table is backed by a shared radix tree indexed by host and path. Each radix tree node carries a view annotation that identifies which views claim a prefix. The recommended representation is a dense bitset for the core view types plus a sparse list for extension views. This allows O(prefix-length) lookup while sharing memory across views.

### 13.4. Incremental Compilation and Versioning

The route table compiler supports incremental compilation: when a config source changes, only the affected view subgraphs are recompiled. The compiler maintains a snapshot of the compiled table plus a bounded delta log. New snapshots and delta-log retention thresholds are implementation-defined. A reasonable default is to create a new snapshot after 500 deltas or 10 seconds, whichever comes first, and to retain the last 5000 deltas. In-flight requests continue using the snapshot they started with.

### 13.5. Hierarchical Gossip

Gossip operates at multiple tiers:

1. **Cluster tier**: Full mesh gossip within a cluster for fast local convergence.
2. **Region tier**: Cluster gateways participate in regional gossip.
3. **Global tier**: Regional gateways gossip across regions.

Gossip bandwidth is adaptive: it increases when churn is detected and decreases during quiescence.

### 13.6. Mesh Routing Scaling

The hierarchical Constellation Mesh Routing design bounds the per-node state and connection count:

- Cluster size is limited to the low hundreds, forming a full mesh.
- Each node maintains two gateway connections plus regional and global gateway paths.
- Cluster link-state databases contain O(cluster_size) entries.
- Regional link-state databases contain O(regional_clusters) entries.
- Global forwarding tables contain O(regions) entries.

### 13.7. Interface Registry Scaling

The interface registry bounds memory through:

1. **TTL expiry**: Remote entries are removed when their TTL expires.
2. **LRU eviction**: When a memory limit is reached, the least-recently-used remote entries are evicted.
3. **Scope-based eviction**: Entries for views the node no longer participates in are evicted.

### 13.8. Latency Targets

The target latency for each routing phase is moderate:

- View derivation: less than 100 microseconds.
- Route table lookup: less than 100 microseconds.
- Interface registry resolution: less than 100 microseconds.
- Mesh router next-hop lookup: less than 100 microseconds.

### 13.9. Update Propagation

Route and view changes SHOULD propagate to interested nodes within seconds. The exact propagation latency depends on gossip tier depth, churn rate, and backoff policy. Constellation Mesh Routing LSA flooding SHOULD converge within a cluster or region in sub-second time and globally within seconds.

## 14. Operational Behavior

### 14.1. Startup

During startup the interface registry is initialized first. It registers interface kinds, discovers local attachments, and begins processing gossip announcements. The Constellation Mesh Router initializes its link-state databases from cached or gossiped LSAs. Then the `RouteManager` compiles the initial route table.

If a route from a static source (Gateway API, xDS, or TOML) references a view that is not declared, or an interface descriptor that is syntactically invalid or uses an unregistered kind, compilation MUST fail and the proxy MUST NOT start.

If a route from a dynamic source (gossip) references a view that is not yet known, compilation MUST NOT fail. The node SHOULD enter discovery for the missing view and MAY start with a partial route table. The proxy MUST reject requests for the missing view until discovery succeeds or an ancestor fallback handles them.

Routes from dynamic sources that contain syntactically invalid interface descriptors or that reference an unregistered interface kind MUST be skipped rather than causing compilation failure.

### 14.2. Hot Reload

When config sources change, the `RouteManager` compiles a new table and swaps it atomically. In-flight requests continue using the table they looked up at the start of the request. The interface registry and Constellation Mesh Router MAY be updated independently of the route table.

### 14.3. Error Handling

A lookup that fails to resolve a view or interface MUST result in a clear error logged at `tracing::error!` level. The response code follows the discovery fallback chain.

### 14.4. Retraction Handling

A `Retraction` gossip payload removes a previously advertised view, interface, target, view-graph edge, or LSA from the receiving node's local state.

1. **Route table**: A retraction that removes a view or interface referenced by a compiled route MUST trigger route table recompilation. If the retraction leaves a prefix without a matching route, the new table reflects that absence; in-flight requests continue using the plan they obtained at request start.
2. **Interface registry**: A retracted remote interface entry MUST be removed from the registry immediately. If the interface is currently in use by an active connection, the implementation MAY keep the connection open until it becomes idle, but the registry MUST NOT select the retracted interface for new requests.
3. **Constellation Mesh Router**: A retracted LSA is treated as an updated LSA with the advertised links removed. The router MUST recompute forwarding tables in the background and MUST NOT disrupt packets already in flight on the previous next hop.
4. **Ordering**: A retraction is identified by the origin `node_id`, the `timestamp` of the envelope, and the retracted entry identifier. A newer announcement from the same origin supersedes an older retraction.
5. **Grace period**: There is no required grace period for retracted state. Implementations MAY apply a short hysteresis before removing interfaces or LSAs to tolerate network reordering, but any hysteresis MUST be bounded and configurable.

## 15. Compatibility

### 15.1. Backward Compatibility

Existing north/south routes that omit the `views`, `strategy`, and `interface` fields MUST continue to behave exactly as before.

### 15.2. Forward Compatibility

New view types, interface descriptor kinds, interface kinds, and forwarding strategies MAY be added without changing the core lookup algorithm, provided they extend the corresponding enums.

## 16. Security Considerations

### 16.1. Threat Model

The route table, interface registry, and Constellation Mesh Routing are high-value targets: an attacker who can modify any of them can redirect traffic across namespaces, exfiltrate east/west traffic through an unexpected interface, or black-hole traffic. This specification assumes that config sources, the `RouteManager`, and the gossip subsystem operate within the same trust boundary as the proxy.

### 16.2. Authentication and Authorization

Cross-namespace visibility MUST be constrained by the authorization rules of the source config. The route table itself does not enforce RBAC; enforcement is the responsibility of the reconciler or translator that produces the table. View derivation from mTLS identity is only trustworthy when mTLS is required for east/west traffic.

Interface registry entries and Constellation Mesh Routing LSAs advertised via gossip MUST be authenticated by the underlying gossip transport. The registry and Constellation Mesh Router MUST ignore announcements from untrusted peers. The specific authentication mechanism (e.g., mTLS, channel binding, signed envelopes) is implementation-defined.

### 16.3. Data Protection

Interface descriptors are opaque tokens. They MUST NOT contain secrets such as private keys or bearer tokens. Any cryptographic material required by iroh MUST be stored separately and loaded by the forwarding layer.

### 16.4. Audit and Logging

Every route table swap, every lookup that resolves to a non-default interface, every interface registry selection, and every Constellation Mesh Routing LSA that changes the local topology SHOULD be logged with the request ID, view, strategy, interface descriptor, and relevant node identifiers. Implementations MAY rate-limit or sample high-cardinality audit events to protect log throughput, provided that every distinct event type is observable at a non-zero sampling rate.

### 16.5. Known Limitations

This document does not specify how iroh interfaces are created, authenticated, or torn down, nor how packets are encapsulated and forwarded over iroh connections. Those concerns are left to the forwarding implementation.

## 17. Deployment Considerations

### 17.1. Kubernetes Manifests

This specification is not Kubernetes-specific. Kubernetes Gateway API resources MAY be used as one config source, but equivalent sources outside Kubernetes MAY also declare views and interface bindings. A full CRD schema is outside the scope of this document.

### 17.2. Resource Requirements

The compiled route table may grow with the product of routes and views. The interface registry may grow with the number of peer nodes and advertised interfaces. The Constellation Mesh Router state grows with cluster size, regional cluster count, and region count. Implementations SHOULD measure memory usage before enabling cross-namespace views at scale.

### 17.3. Migration Path

Existing deployments can adopt this extension incrementally by adding view metadata to new routes while leaving existing routes unchanged. Constellation Mesh Routing can be enabled region-by-region once all nodes in a region support the protocol.

### 17.4. Observability

Metrics SHOULD track lookups per view, per strategy, and per interface descriptor kind, subject to cardinality limits. The interface registry SHOULD emit metrics for registry size, selection outcomes, and remote entry health transitions. The Constellation Mesh Router SHOULD emit metrics for LSA counts, route computation duration, and next-hop changes. Mirror shadow execution SHOULD emit trace events and metrics.

## 18. References

### 18.1. Normative References

[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
           Requirement Levels", BCP 14, RFC 2119, March 1997,
           <https://www.rfc-editor.org/info/rfc2119>.

[RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in
           RFC 2119 Key Words", BCP 14, RFC 8174, May 2017,
           <https://www.rfc-editor.org/info/rfc8174>.

### 18.2. Informative References

[GATEWAY]  Kubernetes SIG-Network, "Gateway API",
           <https://gateway-api.sigs.k8s.io/>.

[IROH]     n0 computer, "iroh", GitHub repository,
           <https://github.com/n0-computer/iroh>.

[PINGORA]  Cloudflare, "Pingora", GitHub repository,
           <https://github.com/cloudflare/pingora>.

[XDS]      Envoy Proxy, "xDS REST and gRPC protocol",
           <https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol>.

## Acknowledgements

This document builds on the existing Sunbeam proxy architecture and on discussions about extending the route table for internal workload routing.

## Author's Address

Name: Sienna Meridian Satterwhite
Organization: Sunbeam Studios
Role: Principal Engineer
Email: sienna@sunbeam.pt
