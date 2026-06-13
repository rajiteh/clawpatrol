# Kubernetes WireGuard dynamic peer pods

Clawpatrol can run in Kubernetes with the gateway as a long-lived pod and
agents as on-demand pods. The gateway keeps using the existing userspace
WireGuard server. Agent pods use a dedicated `clawpatrol k8s-sidecar`
container to create the pod-level WireGuard tunnel; the execution
container remains unprivileged.

## Control flow

1. The agent pod starts with a projected ServiceAccount token whose
   audience is `clawpatrol`.
2. The sidecar generates a WireGuard private key locally and sends only
   the public key plus Kubernetes pod claims to
   `POST /api/dynamic-peers/register`.
3. The gateway selects the `wireguard` dynamic peer transport and the
   named `kubernetes_token_review` authorizer. The authorizer verifies
   the token with Kubernetes TokenReview, reads the live Pod object,
   resolves the pod label configured by `profile_label`, and checks the
   `(namespace, service_account, profile)` allowlist.
4. The gateway allocates a transient WireGuard peer, stores a dynamic
   peer lease, and returns the peer IP, server public key, endpoint, CA
   bundle, and a peer API token for env pushdown.
5. The sidecar creates the TUN device, pins a direct route to the
   gateway endpoint through the pod's original default route, and then
   sends pod default traffic through WireGuard.
6. The sidecar fetches `/api/env-pushdown`, writes `/clawpatrol/env` and
   `/clawpatrol/ca.crt`, writes `/clawpatrol/ready`, and heartbeats until
   shutdown.

## Gateway config

```hcl
gateway {
  dashboard_listen = "0.0.0.0:8080"
  state_dir        = "/opt/clawpatrol"

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

`dynamic_peers` is ignored unless `enabled = true`. In v1 this block is
supported only under `gateway.wireguard`; Tailscale dynamic peers are not
implemented.

## Security boundary

The gateway pod does not need kernel WireGuard privileges because it
runs the existing userspace WireGuard gateway.

The agent pod has two containers:

- `wireguard-sidecar`: owns `/dev/net/tun`, `NET_ADMIN`, the projected
  ServiceAccount token, the WireGuard private key in memory, routing, and
  heartbeats.
- `agent`: has no added capabilities, no Kubernetes API token, no
  `/dev/net/tun`, and a read-only mount of the shared `/clawpatrol`
  volume.

The sidecar never writes the WireGuard private key or peer API token into
the shared volume. The agent gets only the CA bundle, env exports, and
the pod network namespace that the sidecar configured.

## Gateway RBAC

The gateway ServiceAccount needs only:

- `create` on `tokenreviews.authentication.k8s.io`
- `get` on pods in namespaces that can run agents

## Agent pod contract

The sidecar expects these Downward API env vars:

- `POD_NAME`
- `POD_NAMESPACE`
- `POD_UID`
- `NODE_NAME`

The projected ServiceAccount token should use the configured audience:

```yaml
projected:
  sources:
    - serviceAccountToken:
        path: clawpatrol-token
        audience: clawpatrol
        expirationSeconds: 600
```

The agent entrypoint should wait for `/clawpatrol/ready`, then source
`/clawpatrol/env` before starting the actual workload.

## Cleanup

Kubernetes pod peers are transient. The sidecar sends
`POST /api/dynamic-peers/heartbeat` at half the configured TTL and
best-effort deletes the registration on SIGTERM with
`DELETE /api/dynamic-peers/register`. If the pod dies without cleanup,
the gateway sweeper revokes the WireGuard peer, removes the transient
device row, and deletes peer API tokens after the lease expires.

## Limitations

- v1 assumes the gateway is a single active replica with a PVC-backed
  `state_dir`.
- v1 assumes same-cluster networking.
- Peer capacity is bounded by the configured WireGuard IPv4 subnet.
