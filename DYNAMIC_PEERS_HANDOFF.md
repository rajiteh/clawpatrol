# Dynamic Peers Migration Handoff

Date: 2026-06-13

## Goal

Migrate the Kubernetes WireGuard pod work from a bespoke
`kubernetes_registration` implementation to a generic dynamic peer
architecture scoped under the transport config.

Chosen shape:

```hcl
gateway {
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    listen_port = 51820
    endpoint    = "clawpatrol-wg.clawpatrol.svc:51820"

    dynamic_peers {
      enabled   = true
      lease_ttl = "2m"

      authorizer "kubernetes_token_review" "agents" {
        audience      = "clawpatrol"
        profile_label = "clawpatrol.dev/profile"

        allow {
          namespace       = "agents"
          service_account = "agent-runner"
          profiles        = ["default"]
        }
      }
    }
  }
}
```

No legacy compatibility is required. The feature has not shipped, so the old
top-level `kubernetes_registration` block and `/api/k8s/wireguard/*` API paths
were removed rather than aliased.

## What Was Implemented

- Added nested `WireGuardBlock.DynamicPeers` config support in
  `internal/config/config.go`.
- Added generic `DynamicPeersBlock`, labeled
  `authorizer "kubernetes_token_review" "<name>"`, and Kubernetes allow-rule
  structs.
- Replaced old Kubernetes-specific validation with
  `validateWireGuardDynamicPeers`.
- Added generic runtime code in `cmd/clawpatrol/dynamic_peers.go`.
- Introduced these internal boundaries:
  - `dynamicPeerAuthorizer`
  - `dynamicPeerTransport`
  - `dynamicPeerIdentity`
  - `dynamicPeerLease`
  - `wireguardDynamicPeerTransport`
  - `kubernetesTokenReviewAuthorizer`
- Replaced old API paths with:
  - `POST /api/dynamic-peers/register`
  - `POST /api/dynamic-peers/heartbeat`
  - `DELETE /api/dynamic-peers/register`
- The Kubernetes sidecar is `clawpatrol run --tun`, not a dedicated
  subcommand. `--tun` realizes the data plane as a real TUN with
  netns-wide routing (privileged); `--dynamic-peer-authorizer <type>/<name>`
  self-registers as a dynamic peer and renews the lease. The two flags are
  independent identity/transport axes; the privileged sidecar uses them
  together. The register request sends:
  - `transport = "wireguard"`
  - `authorizer = "<name>"` (the name half of `--dynamic-peer-authorizer`)
  - `wireguard_public_key`
  - Kubernetes pod metadata under `claims`
- `--dynamic-peer-authorizer <type>/<name>` mirrors the gateway's
  `authorizer "<type>" "<name>"` block: the type selects the client claims
  provider (`kubernetes_token_review` today), the name is sent on the wire.
  Provider credential is `--kubernetes-token-path` (provider-scoped, not a
  generic flag). Future authorizers add their own `--<provider>-*` flags
  without touching the `--dynamic-peer-*` namespace.
- Replaced the transient lease migration with
  `cmd/clawpatrol/migrations/sqlite/0020_dynamic_peer_leases.sql`.
- Updated docs and examples:
  - `doc/kubernetes-wireguard.md`
  - `doc/wireguard.md`
  - `doc/README.md`
  - `examples/kubernetes/kustomization/`
  - `e2e/kubernetes-wireguard-e2e.sh`
  - `e2e/kubernetes-wireguard-e2e-overlay/`
  - `site/doc/config-reference.md`

## Current Public API

Register request:

```json
{
  "transport": "wireguard",
  "authorizer": "agents",
  "wireguard_public_key": "...",
  "claims": {
    "pod_name": "...",
    "pod_namespace": "...",
    "pod_uid": "...",
    "node_name": "..."
  }
}
```

WireGuard register response:

```json
{
  "transport": "wireguard",
  "peer_ip": "10.55.0.42",
  "peer_ipv6": "fd77::42",
  "server_public_key": "...",
  "endpoint": "...",
  "allowed_ips": ["0.0.0.0/0", "::/0"],
  "mtu": 1420,
  "lease_ttl_seconds": 120,
  "api_token": "...",
  "ca_pem": "..."
}
```

## Lease Model

The new table is `dynamic_peer_leases`.

Important fields:

- `transport`
- `authorizer_type`
- `authorizer_name`
- `subject_key`
- `replacement_key`
- `display_name`
- `owner`
- `profile`
- `wireguard_public_key`
- `peer_ip`
- `metadata_json`
- `expires_ns`
- `last_heartbeat_ns`
- `created_ns`

For Kubernetes:

- `subject_key = "kubernetes:<namespace>:<pod_uid>"`
- `replacement_key = "kubernetes:<namespace>:<pod_name>"`
- `display_name = "<namespace>/<pod_name>"`
- `owner = "system:serviceaccount:<namespace>:<service_account>"`

## Current Limitations

- v1 dynamic peers support only WireGuard transport.
- The Kubernetes TokenReview authorizer is supported only under
  `gateway.wireguard.dynamic_peers`.
- Tailscale behavior is unchanged. The code now has transport and authorizer
  boundaries that can support future Tailscale work, but no Tailscale dynamic
  peer transport has been implemented.
- Run a single active WireGuard-terminating gateway replica. This is a
  pre-existing, gateway-wide constraint — not specific to dynamic peers.
  The WireGuard data plane is an in-process `wireguard-go` device: peers
  are injected into the local device and written to the shared `wg_peers`
  table, but other replicas only read `wg_peers` at boot (`LoadPeers`),
  with no live cross-replica peer-state propagation. Dashboard onboarding
  has the same limitation; dynamic peers just exercise it far harder via
  continuous self-registration and lease expiry, so a peer registered on
  one replica is not usable through another. The server keypair is shared
  (DB-backed), so active/active is not blocked by identity — it is blocked
  by per-replica peer state. Load-balanced or active/active WireGuard
  termination is unsupported in v1.
- The sidecar still requires `NET_ADMIN` and `/dev/net/tun`; the agent
  execution container remains unprivileged.

## Delivery status

Merged into `feat-dynamic-peers`:

- Core generic dynamic-peer architecture (above), with tests.
- Correctness hardening:
  - Delete requires an existing lease — a regular onboarded peer that holds
    a peer API token can no longer revoke its own WireGuard peer / forget
    its device via the dynamic-peer delete path. Delete maps only
    `sql.ErrNoRows` → 404; other DB errors → 500.
  - Same-subject re-registration reuses the IP and swaps the key instead of
    conflicting, so a sidecar that restarts with a fresh key is not locked
    out until the old lease expires.
  - Register rolls back the transport peer + API token if lease persistence
    fails (no orphaned `wg_peers` row / token).
  - The lease sweeper always runs once WireGuard is up, so leases keep
    draining across config reloads / after the feature is disabled.
  - Onboarding and dynamic-peer IP allocation share one lock.
- Single-replica WireGuard caveat documented (see Limitations).

In review (stacked PRs):

- Dashboard observability — `GET /api/dynamic-peers` plus a "Dynamic peers"
  page listing peer / profile / authorizer / heartbeat / expiry / status.
- CLI — `k8s-sidecar` replaced by `clawpatrol run --tun
  --dynamic-peer-authorizer <type>/<name>`. The transport-agnostic
  dynamic-peer client core (`cmd/clawpatrol/dynamic_peer_client.go`) and
  `newWGTransportFromConf` were extracted to pre-stage the gVisor path.

Verification reality for the dev environment: Go is available (module proxy
allowlisted) but there is **no `deno` and no `mise`** (`mise.run` /
`deno.land` return 403) and **no reachable kind cluster**. So Go
builds/tests run locally; the dashboard `deno task format:check` + SPA build
and any `kubectl` validation must run in CI or a real cluster.

## Next steps

1. **Unprivileged gVisor dynamic-peer `run`** — the main follow-up.
   `clawpatrol run --dynamic-peer-authorizer <type>/<name> -- <cmd>` with no
   `--tun`: a single unprivileged container that self-registers and routes a
   wrapped child through the existing gVisor netstack (no `NET_ADMIN`/TUN).
   Design: build a **session-scoped** transport with `newWGTransportFromConf`
   from the registration result and run the gVisor forwarder
   (`startTunBridge` / `enableTransportTCPForwarder`) **in-process**,
   bypassing the per-host singleton daemon (identity is ephemeral and
   lease-bound). Reuse the shared client core for register / heartbeat /
   deregister. Today this combo errors (`--dynamic-peer-authorizer` requires
   `--tun`). Needs a real cluster to verify end-to-end.

2. **End-to-end / kind validation** (intentionally deferred to last).
   Bring up a kind cluster, `kubectl apply` the example manifest, and verify
   the full register → heartbeat → lease-expiry/revocation → graceful
   deregister cycle for an agent pod. The earlier kind blocker was an
   unreachable API server, not the manifest.

3. **Config-time profile cross-check** (minor). `allow { profiles = [...] }`
   is validated against declared policy profiles only at register time
   (`dynamicPeerProfileExists`); a compile-time cross-check would fail fast
   on a typo, if the validator can reach the policy profile set.

4. **Confirm `apiConfigApply` reload semantics** (minor). The always-on
   sweeper covers both restart and hot-reload, but the exact reload behavior
   was never traced — document it.
