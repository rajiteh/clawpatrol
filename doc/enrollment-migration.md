# Migrating to workload enrollment

This guide migrates an existing clawpatrol deployment from the old
"dynamic peers" shape (`gateway.wireguard.dynamic_peers { ... }` +
`clawpatrol run --tun`) to the current enrollment design (top-level
labeled `enrollment "<type>" "<name>"` blocks — siblings of `profile` /
`credential` — plus `clawpatrol bridge`).

> Already on the interim `gateway.enrollment { peer_ttl = ...; authorizer
> "<type>" "<name>" { allow { ... } } }` shape? Skip to
> [§1b](#1b-interim-enrollment-shape) for the small change: the whole
> block moves out of `gateway { ... }` to the top level, the `authorizer`
> sub-block's two labels move up onto `enrollment` itself, `allow { ... }`
> rules become `match { ... }` blocks, `peer_ttl` is replaced by the
> derived liveness window (`keepalive_interval × timeout_multiplier`), and
> an optional `max_ttl` slot is now accepted.

No data migration is needed: the storage migration
(`0020_wg_peer_enrollment.sql`) runs automatically on gateway startup
and adds the enrollment columns to `wg_peers`. The old
`dynamic_peer_leases` table is simply no longer used.

## 1. Gateway config

Move the block out of `gateway.wireguard` and up to a top-level
`enrollment "<type>" "<name>"` block (a sibling of the `gateway` block,
like `profile` / `credential`). Drop `enabled` (presence of at least one
enrollment block is what enables it). The old `authorizer "<type>"
"<name>"` sub-block's two labels move onto the `enrollment` block itself;
each `allow { ... }` rule becomes a `match { ... }` block; `lease_ttl` is
replaced by the derived liveness window (`keepalive_interval ×
timeout_multiplier`).

**Before:**

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

**After:**

```hcl
gateway {
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    listen_port = 51820
    endpoint    = "clawpatrol-wg.clawpatrol.svc:51820"
  }
}

enrollment "kubernetes_token_review" "agents" {
  audience = "clawpatrol"

  match {
    namespace       = "agents"
    service_account = "agent-runner"
    profile_label   = "clawpatrol.dev/profile"
    profiles        = ["default"]
  }

  # Liveness is derived: keepalive_interval × timeout_multiplier (60s×3 = 3m).
  keepalive_interval = "60s"
  timeout_multiplier = 3
  # max_ttl = "24h"   # optional; parsed + stored, not enforced yet
}
```

Notes:
- The liveness window is derived, not set directly: `keepalive_interval`
  (default 25s, min 10s) × `timeout_multiplier` (default 3; `0` disables
  reaping). It is not a heartbeat TTL — the gateway reaps a peer once its
  WireGuard `rx_bytes` has been quiet for that long. Because the window is
  a whole number of keepalives, the reap-vs-keepalive safety ratio can't be
  misconfigured; the old `peer_ttl = "3m"` maps to `60s × 3`.
- `profile_label` is optional per `match` (default
  `clawpatrol.dev/profile`). The pod's profile is read from that label
  and must be in the match's `profiles` allowlist.
- `max_ttl` is optional; it is parsed and stored for a future
  hard-expiry pass but not enforced yet.
- Validate before rolling out: `clawpatrol validate gateway.hcl`.

## 1b. Interim enrollment shape

If you already migrated off `dynamic_peers` onto the interim
`gateway.enrollment { peer_ttl = ...; authorizer "<type>" "<name>"
{ ... } }` shape, the change is placement plus block shape:

- move the block out of `gateway { ... }` to the top level:
  `gateway { enrollment { authorizer "<type>" "<name>" { ... } } }` →
  top-level `enrollment "<type>" "<name>" { ... }` (the authorizer's two
  labels move up onto `enrollment`; there is no longer a wrapping
  `enrollment { ... }` container or a nested `authorizer` block).
- each `allow { namespace, service_account, profiles }` →
  `match { namespace, service_account, profile_label?, profiles }`.
- the enrollment-wide `peer_ttl` → per-block `keepalive_interval` ×
  `timeout_multiplier` (derived liveness window).
- new optional `max_ttl` slot (parsed + stored, not yet enforced).

Multiple authorizers that used to be sibling `authorizer` blocks under
one `enrollment` become multiple top-level `enrollment "<type>"
"<name>"` blocks, one per name.

## 2. Agent sidecar invocation

The sidecar verb changed from `run --tun` to `bridge`, and
`--dynamic-peer-authorizer` is now `--authorizer`. All other flags are
unchanged.

**Before:**

```yaml
args:
  - run
  - --tun
  - --gateway-url=http://clawpatrol-api.clawpatrol.svc:8080
  - --dynamic-peer-authorizer=kubernetes_token_review/agents
  - --kubernetes-token-path=/var/run/secrets/tokens/clawpatrol-token
  - --env-out=/clawpatrol/env
  - --ca-out=/clawpatrol/ca.crt
  - --ready-file=/clawpatrol/ready
```

**After:**

```yaml
args:
  - bridge
  - --gateway-url=http://clawpatrol-api.clawpatrol.svc:8080
  - --authorizer=kubernetes_token_review/agents
  - --kubernetes-token-path=/var/run/secrets/tokens/clawpatrol-token
  - --env-out=/clawpatrol/env
  - --ca-out=/clawpatrol/ca.crt
  - --ready-file=/clawpatrol/ready
```

Everything else about the pod is unchanged: the `restartPolicy: Always`
native sidecar, the `/clawpatrol/ready` startup probe, `NET_ADMIN` +
`/dev/net/tun`, the projected ServiceAccount token, the Downward API
`POD_*` / `NODE_NAME` env, and the unprivileged sibling workload
container that reads the handoff files.

## 3. Roll out

1. Apply the new gateway config and restart the gateway pod. The DB
   migration runs on startup; existing onboarded devices are untouched.
2. Update the agent pod spec (or its template / admission injector) to
   the new args and the new image. The bridge sidecar enrolls
   automatically; note the register endpoint moved from
   `/api/dynamic-peers/register` to `/api/enrollment/register`, so the
   gateway and the sidecar image must be upgraded together.
3. Old agent pods running `run --tun` keep working against their
   existing peer until they terminate (the WireGuard peer persists and
   their keepalive traffic keeps it live); they will not re-enroll
   against the new gateway, so roll them once the gateway is upgraded.

## What was removed

- The `dynamic_peers { enabled = ... }` nested block and the `enabled`
  flag.
- `lease_ttl` / the interim `peer_ttl` (replaced by the derived liveness
  window, `keepalive_interval × timeout_multiplier`).
- The interim nested `authorizer "<type>" "<name>"` block and its
  `allow { ... }` rules (replaced by labels on `enrollment` and
  `match { ... }` blocks).
- The application heartbeat and the `POST /api/dynamic-peers/heartbeat`
  endpoint — liveness is now driven by WireGuard `rx_bytes`.
- The dashboard's separate "Dynamic peers" page — enrolled peers now
  appear in the regular Devices list.

## Quick checklist for an automated migration

- [ ] Move `dynamic_peers { ... }` out of `wireguard` to a top-level
      `enrollment "<type>" "<name>" { ... }` block (sibling of `gateway`).
- [ ] Delete the `enabled` line.
- [ ] Lift the `authorizer "<type>" "<name>"` labels onto the
      `enrollment` block; drop the now-empty `authorizer` wrapper.
- [ ] Turn each `allow { ... }` rule into a `match { ... }` block.
- [ ] Replace `lease_ttl` / `peer_ttl` with `keepalive_interval` +
      `timeout_multiplier` (liveness = interval × multiplier; e.g.
      `3m` → `60s × 3`).
- [ ] In every agent pod spec: replace the `run` + `--tun` args with a
      single `bridge` arg.
- [ ] Rename `--dynamic-peer-authorizer=` → `--authorizer=`.
- [ ] `clawpatrol validate <config>` then restart the gateway, then
      roll the agent pods.
