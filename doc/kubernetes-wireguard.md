# Kubernetes WireGuard agent pods

Clawpatrol can run in Kubernetes with the gateway as a long-lived pod and
agents as on-demand pods. The gateway keeps using the existing userspace
WireGuard server. Agent pods use a native Kubernetes sidecar init container
running `clawpatrol agent` to bring up the pod-level WireGuard tunnel; the
execution container remains unprivileged.

`clawpatrol agent` is a foreground, privileged data plane: it self-enrolls
through a configured authorizer, brings up a userspace WireGuard TUN, and
routes the whole pod network namespace through the gateway. It stays up for
the netns lifetime and best-effort deregisters on SIGTERM. The execution
workload runs in a sibling, unprivileged container that shares this netns
and reads the handoff files the agent writes.

```
clawpatrol agent \
  --gateway-url=http://clawpatrol-api.clawpatrol.svc:8080 \
  --authorizer=kubernetes_token_review/agents \
  --kubernetes-token-path=/var/run/secrets/tokens/clawpatrol-token \
  --env-out=/clawpatrol/env --ca-out=/clawpatrol/ca.crt --ready-file=/clawpatrol/ready
```

The `--authorizer <type>/<name>` value mirrors the gateway's
`authorizer "<type>" "<name>"` block: the type selects the client-side
claims provider (`kubernetes_token_review` reads the projected
ServiceAccount token and the downward-API `POD_*` env), and the name picks
the configured server authorizer.

## Control flow

1. The agent pod starts the `wireguard-sidecar` init container with
   `restartPolicy: Always` and a projected ServiceAccount token whose
   audience is `clawpatrol`.
2. The sidecar generates a WireGuard private key locally and sends only
   the public key plus Kubernetes pod claims to
   `POST /api/dynamic-peers/register`.
3. The gateway selects the `wireguard` transport and the named
   `kubernetes_token_review` authorizer. The authorizer verifies the token
   with Kubernetes TokenReview, reads the live Pod object, resolves the pod
   label configured by `profile_label`, and checks the
   `(namespace, service_account, profile)` allowlist. The profile is always
   server-derived from the Pod — never submitted by the client.
4. The gateway allocates a WireGuard peer, marks the `wg_peers` row as
   enrolled (with the resolved identity), and returns the peer IP, server
   public key, endpoint, CA bundle, and a peer API token for env pushdown.
5. The sidecar creates the TUN device, pins a direct route to the gateway
   endpoint through the pod's original default route, and then sends pod
   default traffic through WireGuard with persistent keepalive.
6. The sidecar fetches `/api/env-pushdown`, writes `/clawpatrol/env` and
   `/clawpatrol/ca.crt`, writes `/clawpatrol/ready`, and passes its startup
   probe. There is no application heartbeat — the keepalive traffic itself
   is the liveness signal (see Cleanup).

## Gateway config

```hcl
gateway {
  dashboard_listen = "0.0.0.0:8080"
  state_dir        = "/opt/clawpatrol"

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

The top-level `enrollment` block enables workload self-enrollment; it is
active as soon as it declares at least one `authorizer`. Enrollment requires
a `wireguard` block (the only transport in v1). `peer_ttl` is the liveness
window the reaper enforces (default `3m`).

## Security boundary

The gateway pod does not need kernel WireGuard privileges because it runs
the existing userspace WireGuard gateway.

The agent pod declares one native sidecar init container and one app
container:

- `wireguard-sidecar`: declared under `initContainers` with
  `restartPolicy: Always`; owns `/dev/net/tun`, `NET_ADMIN`, the projected
  ServiceAccount token, the WireGuard private key in memory, and routing.
- `agent`: has no added capabilities, no Kubernetes API token, no
  `/dev/net/tun`, and a read-only mount of the shared `/clawpatrol`
  volume.

The sidecar never writes the WireGuard private key or peer API token into
the shared volume. The agent gets only the CA bundle, env exports, and the
pod network namespace that the sidecar configured.

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

The sidecar should use a startup probe that checks `/clawpatrol/ready` so
Kubernetes starts the agent container only after tunnel setup and env/CA
handoff succeed.

The agent entrypoint should wait for `/clawpatrol/ready`, then source
`/clawpatrol/env` before starting the actual workload.

## Example Deployment

The Kubernetes example is a Kustomize base:

```bash
kubectl apply -k examples/kubernetes/kustomization
```

The example creates the `clawpatrol` gateway namespace and the `agents`
workload namespace, plus the minimal TokenReview and pod-read RBAC.

The local e2e overlay is checked in separately and patches the base to use
isolated `*-e2e` namespaces, the local kind image tag, and a shorter
`peer_ttl`:

```bash
kubectl kustomize e2e/kubernetes-wireguard-e2e-overlay
```

For a local kind validation run that builds the current workspace image,
uses that e2e overlay, and cleans up after itself:

```bash
./e2e/kubernetes-wireguard-e2e.sh
```

### Optional: admission-based injection

The example pod spec is the supported baseline — it spells out the sidecar,
volumes, and token projection explicitly, so it works on any cluster with no
extra controllers. Auto-injecting the sidecar with a `MutatingAdmissionPolicy`
(or a mutating webhook) is a purely ergonomic layer on top; it is not
required, and nothing in the enrollment path depends on it.

## Cleanup

Kubernetes pod peers are transient. There is no application heartbeat: the
gateway observes liveness from the WireGuard device, where persistent
keepalive advances each peer's `rx_bytes` roughly every 25s. A freshly
enrolled peer gets a full `peer_ttl` grace window before it is eligible for
reaping.

- On SIGTERM the sidecar best-effort deletes its registration with
  `DELETE /api/dynamic-peers/register`, which revokes the WireGuard peer,
  drops the enrolled `wg_peers` row, and deletes its peer API tokens.
- If the pod dies without cleanup, the reaper notices that the peer's
  `rx_bytes` has stopped advancing past `peer_ttl` and revokes it the same
  way. `last_handshake` is surfaced as a diagnostic only (it moves on
  rekey, not on every keepalive), so liveness is never driven off it.

The reaper only ever touches enrolled rows (`enrolled = 1`), so durably
onboarded devices are never reaped.

## Limitations

- v1 assumes the gateway is a single active replica with a PVC-backed
  `state_dir`.
- v1 assumes same-cluster networking.
- Peer capacity is bounded by the configured WireGuard IPv4 subnet.
