# Migrating to workload enrollment

This guide migrates an existing clawpatrol deployment from the old
"dynamic peers" shape (`gateway.wireguard.dynamic_peers { ... }` +
`clawpatrol run --tun`) to the new enrollment design (top-level
`enrollment { ... }` + `clawpatrol bridge`).

No data migration is needed: the storage migration
(`0020_wg_peer_enrollment.sql`) runs automatically on gateway startup
and adds the enrollment columns to `wg_peers`. The old
`dynamic_peer_leases` table is simply no longer used.

## 1. Gateway config

Move the block out of `gateway.wireguard` and up to a top-level
`enrollment` block. Drop `enabled` (presence + an authorizer is what
enables it) and rename `lease_ttl` → `peer_ttl`. The `authorizer` and
`allow` blocks are unchanged.

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

  enrollment {
    peer_ttl = "3m"

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
```

Notes:
- `peer_ttl` is the liveness window (default `3m`). It is no longer a
  heartbeat TTL — the gateway reaps a peer once its WireGuard `rx_bytes`
  has been quiet for longer than `peer_ttl`. Keep it comfortably above
  the keepalive interval (25s); `2m`–`3m` is fine.
- Validate before rolling out: `clawpatrol validate gateway.hcl`.

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
- `lease_ttl` (replaced by `peer_ttl`).
- The application heartbeat and the `POST /api/dynamic-peers/heartbeat`
  endpoint — liveness is now driven by WireGuard `rx_bytes`.
- The dashboard's separate "Dynamic peers" page — enrolled peers now
  appear in the regular Devices list.

## Quick checklist for an automated migration

- [ ] Move `dynamic_peers { ... }` out of `wireguard` to a top-level
      `enrollment { ... }`.
- [ ] Delete the `enabled` line.
- [ ] Rename `lease_ttl` → `peer_ttl` (and bump to ≥ `2m` if it was
      shorter than the keepalive interval).
- [ ] In every agent pod spec: replace the `run` + `--tun` args with a
      single `bridge` arg.
- [ ] Rename `--dynamic-peer-authorizer=` → `--authorizer=`.
- [ ] `clawpatrol validate <config>` then restart the gateway, then
      roll the agent pods.
