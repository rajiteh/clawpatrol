# Kubernetes WireGuard agent pods

Clawpatrol can run in Kubernetes with the gateway as a long-lived pod and
agents as on-demand pods. The gateway keeps using the existing userspace
WireGuard server. Agent pods use a native Kubernetes sidecar init container
running `clawpatrol bridge` to bring up the pod-level WireGuard tunnel; the
execution container remains unprivileged.

`clawpatrol bridge` is a foreground, privileged data plane: it self-enrolls
through a configured authorizer, hosts a userspace WireGuard tunnel, and
routes the whole pod network namespace through the gateway — bridging the
pod's netns to the gateway. It stays up for the netns lifetime and
best-effort deregisters on SIGTERM. The execution workload runs in a
sibling, unprivileged container that shares this netns and reads the handoff
files the bridge writes.

```
clawpatrol bridge \
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
   `POST /api/enrollment/register`.
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
}

enrollment "kubernetes_token_review" "agents" {
  audience = "clawpatrol"

  match {
    namespace       = "agents"
    service_account = "agent-runner"
    profile_label   = "clawpatrol.dev/profile"
    profiles        = ["default"]
  }

  # Liveness is derived: keepalive_interval × keepalive_reap_count.
  # Here 25s × 3 = a 75s reap window. A longer interval means fewer keepalive
  # packets and a longer window; there is no upper bound.
  keepalive_interval = "25s"
  keepalive_reap_count = 3
}
```

Each top-level `enrollment "<type>" "<name>"` block — a sibling of
`profile` / `credential`, not nested in `gateway { ... }` — enables workload
self-enrollment through one authorizer; the two labels are the authorizer
type and the instance name (the `--authorizer <type>/<name>` the sidecar
dials). Enrollment requires a `wireguard` block (the only transport in v1).
Each
`match` block is one identity → profile-binding rule: a pod is matched on
`namespace` + `service_account`, its profile is read from the pod label
named by `profile_label` (default `clawpatrol.dev/profile`), and that value
must be in the match's `profiles` allowlist. `keepalive_interval` (default
25s, minimum 10s) is the WireGuard persistent-keepalive cadence the sidecar
applies; `keepalive_reap_count` (default 3, or 0 to disable reaping) is how
many missed keepalives elapse before the reaper revokes a peer. The liveness
window is derived — `keepalive_interval × keepalive_reap_count` — so the
reap-vs-keepalive safety ratio is an integer that can't be misconfigured, and
the gateway pushes the resolved keepalive to the sidecar at enroll.

There is no upper bound on `keepalive_interval` — a longer interval just means
fewer keepalive packets and a longer liveness window, a policy choice left to
the operator. (An earlier build capped it at 25s for WireGuard rekey safety;
that is moot now that the sidecar is the sole keepalive sender and checks
liveness with an active ICMP probe that also drives rekeying off real traffic —
see Cleanup below.) The 10s floor is set by the reaper's 20s sample cadence:
the smallest window (`EnrollmentMinReapCount × keepalive`) must be at least one
sample interval to remain resolvable.

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
liveness window (a small `keepalive_interval` so reaping happens quickly):

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
gateway observes liveness from the WireGuard device, where the **sidecar is the
sole (authoritative) keepalive sender** — the gateway does not keepalive back.
That is deliberate: wireguard-go rearms its persistent-keepalive timer on any
authenticated packet, including received ones, so with both peers sending, one
direction's traffic perpetually postpones the other's keepalive and a healthy
idle peer can show flat `rx_bytes` in one direction and be falsely reaped. With
only the client sending, client→gateway `rx_bytes` advances deterministically
every `keepalive_interval`, so the reaper sees true liveness. A freshly
enrolled peer gets a full liveness window
(`keepalive_interval × keepalive_reap_count`) before it is eligible for
reaping.

- On SIGTERM the sidecar best-effort deletes its registration with
  `DELETE /api/enrollment/register`, which revokes the WireGuard peer,
  drops the enrolled `wg_peers` row, and deletes its peer API tokens.
- If the pod dies without cleanup, the reaper notices that the peer's
  `rx_bytes` has stopped advancing past the liveness window and revokes it
  the same way. `last_handshake` is surfaced as a diagnostic only (it moves
  on rekey, not on every keepalive), so liveness is never driven off it.

The reaper only ever touches enrolled rows (`enrolled = 1`), so durably
onboarded devices are never reaped.

The sidecar recovers on its own when the tunnel goes quiet, independent of the
reaper, using an **active ICMP-echo probe** rather than watching `rx_bytes`
(which is normally quiet on an idle tunnel now that the gateway does not
keepalive back). While `rx_bytes` advances there is nothing to do; when it goes
quiet the watchdog sends an ICMP echo to the gateway's tunnel address — a
round-trip reply proves both directions — and escalates only on sustained
failure. After a client-configurable number of failed probes
(`--local-reset-missed`, default 2, clamped below the server reap count; `0`
disables) it rekeys in place, and past the reap count it tears the tunnel down
and **re-enrolls in process**. It does not exit the container to recover: a
`restartPolicy: Always` native sidecar restarts into the same pod sandbox and
resets nothing a device rebuild doesn't (recovery therefore leaves the restart
count untouched — lifecycle logs, not restart count, are the signal). During
the gap `clawpatrol0` is torn down, so the pod has no default route and the
workload's general egress fails closed rather than leaking out untunneled. Each
reconnect re-reads `/etc/resolv.conf` and re-discovers the underlay, reconciling
the control-plane host routes it pins to the pod's underlay — the gateway
API/endpoint and the DNS resolvers, tagged with a dedicated route protocol
(`--route-proto`, default `111`) so they survive with no default route and can
be found again. It re-enrolls with a fresh key and reuses its prior peer IP for
the same subject.

## Restricting pod egress (recommended)

The fail-closed routing above means a workload cannot reach off-cluster
destinations untunneled, even mid-self-heal. As a second, cluster-enforced
layer, restrict the agent pod's egress to only the gateway (API + WireGuard
endpoint) and cluster DNS with a NetworkPolicy — see
[`examples/kubernetes/agent-egress-networkpolicy.yaml`](https://github.com/denoland/clawpatrol/blob/main/examples/kubernetes/agent-egress-networkpolicy.yaml).
It is optional defense-in-depth (not part of the Kustomization base) and only
takes effect on a CNI that enforces NetworkPolicy.

## Limitations

- v1 assumes the gateway is a single active replica with a PVC-backed
  `state_dir`.
- v1 assumes same-cluster networking.
- Peer capacity is bounded by the configured WireGuard IPv4 subnet.
