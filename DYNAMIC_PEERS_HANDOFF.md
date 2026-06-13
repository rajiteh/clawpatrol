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
  - `examples/kubernetes-wireguard.yaml`
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

## Validation Already Run

Passed:

```bash
mise exec -- gofmt -l .
mise exec -- env GOCACHE=/tmp/clawpatrol-go-cache GOFLAGS=-mod=readonly go test ./...
ruby -e 'require "yaml"; docs = YAML.load_stream(File.read("examples/kubernetes-wireguard.yaml")); abort "no docs" if docs.empty?; puts "parsed #{docs.size} Kubernetes documents"'
```

The YAML parse reported 13 Kubernetes documents.

Blocked:

```bash
mise exec -- kubectl apply --dry-run=client --validate=false -f examples/kubernetes-wireguard.yaml
mise exec -- kubectl get namespace clawpatrol agents
```

Both failed because the configured kind API endpoint was unreachable:

```text
The connection to the server 127.0.0.1:33137 was refused
```

This failure occurred both inside the sandbox and after escalation, so the
blocker appears to be the local kind cluster/API server state rather than the
manifest changes.

## Next Session Checklist

1. Confirm whether the kind cluster should be restarted or recreated.
2. Re-run:

   ```bash
   mise exec -- kubectl get namespace clawpatrol agents
   mise exec -- kubectl apply --dry-run=client --validate=false -f examples/kubernetes-wireguard.yaml
   ```

3. Consider adding broader tests for:
   - `apiDynamicPeerRegister` request routing and response shape.
   - register conflict cases with fake authorizer and fake transport.
   - sidecar HTTP request construction for `claims`.
   - malformed `transport` and missing `authorizer` API requests.
4. Check git staging before committing. The worktree had pre-existing staged
   additions from the first Kubernetes implementation. Use `git add -A` if the
   intent is to commit the final dynamic-peer shape.

## Files To Revisit

- `cmd/clawpatrol/dynamic_peers.go`
- `cmd/clawpatrol/k8s_sidecar_linux.go`
- `internal/config/config.go`
- `internal/config/dump.go`
- `internal/config/compile_test.go`
- `cmd/clawpatrol/k8s_registration_test.go`
- `cmd/clawpatrol/migrations/sqlite/0020_dynamic_peer_leases.sql`
- `examples/kubernetes-wireguard.yaml`
- `doc/kubernetes-wireguard.md`
- `site/doc/config-reference.md`
