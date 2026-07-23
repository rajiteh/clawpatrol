# Kubernetes Enrollment

Claw Patrol can run inside Kubernetes with one long-lived gateway pod
and stateless agent pods that appear only for the lifetime of a job.
The gateway still uses the WireGuard transport, but agent pods do not
need a pre-created peer or a human approval flow. Instead, each pod
**self-enrolls** as a transient WireGuard peer using its projected
Kubernetes ServiceAccount token.

This mode is for same-cluster deployments where:

- the gateway runs in Kubernetes,
- agent pods are spawned on demand,
- the agent execution container must stay restricted,
- a privileged networking helper is acceptable outside the execution
  container.

Enrollment is configured with one or more top-level labeled
`enrollment "<type>" "<name>"` blocks — siblings of `profile` /
`credential`, not nested in `gateway { ... }`. The Kubernetes authorizer
ships in-tree; it requires a `wireguard` block (the only transport in
v1).

## Architecture

The deployment has three parts:

- **Gateway pod** — runs `clawpatrol gateway`, the dashboard/API, and
  the userspace WireGuard server. It needs Kubernetes API permission to
  create TokenReviews and read allowed agent pods.
- **WireGuard sidecar init container** — runs `clawpatrol bridge` with
  `restartPolicy: Always`. It owns `/dev/net/tun`, `NET_ADMIN`, pod
  routing, the projected ServiceAccount token, enrollment, hosting the
  userspace WireGuard tunnel, and best-effort deregistration on shutdown.
- **Agent container** — runs the actual workload. It has no Kubernetes
  token, no `/dev/net/tun`, no added capabilities, and only a read-only
  shared handoff volume.

Kubernetes native sidecars are declared under `initContainers` with
`restartPolicy: Always`. The sidecar starts before the app container,
continues running while the app runs, and is terminated after the app
container. Add a startup probe that checks `/clawpatrol/ready` so the
agent does not start until tunnel setup and env/CA handoff have
succeeded.

## Gateway config

Add a top-level `enrollment "kubernetes_token_review" "<name>"` block — a
sibling of `profile` / `credential`, not nested in `gateway { ... }`:

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

  # Liveness is derived: keepalive_interval × keepalive_reap_count (25s×3 = 75s).
  # A longer interval means fewer keepalive packets and a longer window; there
  # is no upper bound.
  keepalive_interval = "25s"
  keepalive_reap_count = 3
}

profile "default" {
  credentials = []
}
```

The block takes two labels: the authorizer type
(`kubernetes_token_review`) and an instance name (`agents`). The
authorizer verifies the pod's projected ServiceAccount token with
Kubernetes TokenReview, reads the live Pod object, matches the pod's
namespace + ServiceAccount against a `match` block, and selects the Claw
Patrol profile from the pod label named by that match's `profile_label`
(default `clawpatrol.dev/profile`). The value must appear in the match's
`profiles` allowlist. The client does not get to submit its own profile.
Add more `match { ... }` blocks to bind additional identities.

`keepalive_interval` (default 25s, minimum 10s) is the WireGuard
persistent-keepalive cadence the sidecar applies; `keepalive_reap_count`
(default 3, or 0 to disable) is how many missed keepalives elapse before the
reaper revokes a peer. The liveness window is derived — `keepalive_interval ×
keepalive_reap_count` — so the safety ratio is an integer that can't be
misconfigured, and the resolved keepalive is pushed to the sidecar at enroll.

There is no upper bound on `keepalive_interval` — a longer interval just means
fewer keepalive packets and a longer liveness window, left to the operator. (An
earlier build capped it at 25s for WireGuard rekey safety; that is moot now
that the sidecar is the sole keepalive sender and checks liveness with an
active ICMP probe that also drives rekeying off real traffic — see the
lifecycle below.) The 10s floor is set by the reaper's 20s sample cadence: the
smallest window must stay at least one sample wide.

The complete standalone HCL example lives at
[`examples/wireguard-enrollment-kubernetes.hcl`](https://github.com/denoland/clawpatrol/blob/main/examples/wireguard-enrollment-kubernetes.hcl).

## Agent pod contract

The sidecar needs:

- `NET_ADMIN`
- `/dev/net/tun`
- a projected ServiceAccount token with the configured audience
- Downward API env vars for pod name, namespace, UID, and node name
- read-write access to a shared `emptyDir` handoff volume

The agent container should not mount the Kubernetes token or
`/dev/net/tun`, should not add Linux capabilities, and should mount the
handoff volume read-only.

```yaml
initContainers:
  - name: wireguard-sidecar
    restartPolicy: Always
    image: ghcr.io/denoland/clawpatrol:latest
    args:
      - bridge
      - --gateway-url=http://clawpatrol-api.clawpatrol.svc:8080
      - --authorizer=kubernetes_token_review/agents
      - --kubernetes-token-path=/var/run/secrets/tokens/clawpatrol-token
      - --env-out=/clawpatrol/env
      - --ca-out=/clawpatrol/ca.crt
      - --ready-file=/clawpatrol/ready
    startupProbe:
      exec:
        command: ["test", "-f", "/clawpatrol/ready"]
      periodSeconds: 1
      failureThreshold: 120
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        add: ["NET_ADMIN"]
```

The sidecar writes only the env exports, CA bundle, and ready marker to
the shared volume. It keeps the WireGuard private key and peer API token
out of the agent-visible filesystem.

The full pod example is in the Kustomize base at
[`examples/kubernetes/kustomization`](https://github.com/denoland/clawpatrol/tree/main/examples/kubernetes/kustomization).

The explicit pod spec is the supported baseline and needs no extra
controllers. Auto-injecting the sidecar with a `MutatingAdmissionPolicy`
(or a mutating webhook) is an optional ergonomic layer; nothing in the
enrollment path depends on it.

## Deploy the example

The example base creates:

- `clawpatrol` namespace for the gateway,
- `agents` namespace for agent pods,
- gateway StatefulSet and services,
- TokenReview and pod-read RBAC,
- a sample restricted agent pod with the WireGuard sidecar init
  container.

```bash
kubectl apply -k examples/kubernetes/kustomization
```

The gateway ServiceAccount needs only:

- `create` on `tokenreviews.authentication.k8s.io`
- `get` on pods in namespaces that can run agent pods

The WireGuard endpoint in the example uses same-cluster Service DNS:

```hcl
endpoint = "clawpatrol-wg.clawpatrol.svc:51820"
```

## Enrollment lifecycle

On startup, the sidecar:

1. generates a WireGuard private key locally,
2. sends only the public key and Kubernetes pod claims to
   `POST /api/enrollment/register`,
3. receives WireGuard client config, CA PEM, and a peer API token,
4. brings up the TUN device and routes pod traffic through it with
   persistent keepalive,
5. fetches env pushdown and writes `/clawpatrol/env`,
   `/clawpatrol/ca.crt`, and `/clawpatrol/ready`.

There is no application heartbeat. The **sidecar is the sole (authoritative)
keepalive sender** — the gateway does not keepalive back. That is deliberate:
wireguard-go rearms its persistent-keepalive timer on any authenticated packet,
including received ones, so with both peers sending, one direction's traffic
perpetually postpones the other's keepalive and a healthy idle peer can show
flat `rx_bytes` in one direction and be falsely reaped. With only the client
sending, client→gateway `rx_bytes` advances deterministically every
`keepalive_interval`, so the gateway's reaper observes true liveness: a peer
whose `rx_bytes` stops advancing past the liveness window (`keepalive_interval
× keepalive_reap_count`) is reaped, and a freshly enrolled peer gets a full
window first. On shutdown the sidecar best-effort deregisters; either way the
gateway revokes the transient WireGuard peer and clears its enrolled
`wg_peers` row.

The sidecar checks its own direction with an **active ICMP-echo probe**, not
by watching `rx_bytes` (which is normally quiet on an idle tunnel now that the
gateway does not keepalive back). While `rx_bytes` advances there is nothing to
do. When it goes quiet the watchdog sends an ICMP echo to the gateway's tunnel
address — a round-trip reply proves both directions — and escalates only on
sustained failure: after `--local-reset-missed` (default 2, clamped below the
reap count) consecutive failed probes it rekeys in place, and past the reap
count it tears the tunnel down and **re-enrolls in process**. It does not exit
the container to recover: a native-sidecar restart lands in the same pod
sandbox and resets nothing a device rebuild doesn't. During the gap
`clawpatrol0` is gone, so the pod has no default route and the workload's
general egress fails closed until the tunnel is rebuilt. Each reconnect
re-reads `/etc/resolv.conf` and re-discovers the underlay, reconciling the
control-plane host routes it pins to the pod's underlay (the gateway API, the
WireGuard endpoint, and the DNS resolvers, tagged with a dedicated route
protocol — `--route-proto`, default `111` — so they survive with no default
route and are found again). It re-enrolls with a fresh key, reusing its prior
peer IP for the same subject. Because DNS stays reachable, the gateway is
resolved by name, so its TLS SNI and `Host` are unaffected. Recovery leaves the
container restart count untouched, so lifecycle logging (enroll, rekey, and
reconnect transitions) — not restart count — is the operator signal.

Enrolled peers show up in the dashboard's Devices list alongside onboarded
devices, distinguished by their `authorizer/subject` name. The device detail
page adds an Enrollment panel showing the authorizer, subject, enrolled time,
keepalive, derived liveness window, and last heartbeat with a missed-beat
counter, plus a live/stale indicator. The profile is shown read-only (it is
assigned from the pod label) and the delete action is hidden, since the peer
is reaper-managed.

## Restricting pod egress (recommended)

The sidecar already fails closed at the routing layer, so a workload cannot
reach off-cluster destinations untunneled even during a self-heal gap. For a
second, cluster-enforced layer, pin the agent pod's allowed egress to exactly
the paths enrollment needs — the gateway (API + WireGuard endpoint) and
cluster DNS — with a NetworkPolicy. A ready-to-adapt example is at
[`examples/kubernetes/agent-egress-networkpolicy.yaml`](https://github.com/denoland/clawpatrol/blob/main/examples/kubernetes/agent-egress-networkpolicy.yaml).
It is defense-in-depth, not a dependency: it is not part of the Kustomization
base, and it only takes effect on a CNI that enforces NetworkPolicy (Calico,
Cilium, and similar; kind's default kindnet does not).

## Local e2e

The repository includes a kind-based e2e flow that uses the same
Kustomize base plus an e2e overlay:

```bash
./e2e/kubernetes-wireguard-e2e.sh
```

The test builds the current workspace image, loads it into kind,
applies the e2e overlay, waits for the agent handoff, verifies the
restricted agent contract, checks traffic through the tunnel, confirms
rx_bytes liveness holds a live peer past the derived liveness window,
exercises the sidecar self-heal (scale the gateway to 0 → the ICMP probe
fails → the sidecar fails closed and re-enrolls in process with a fresh key,
with no container restart), and verifies peer cleanup.

## Limitations

- v1 assumes the gateway and agents run in the same Kubernetes cluster.
- v1 assumes a single active WireGuard gateway replica.
- The gateway does not need kernel WireGuard privileges; it runs the
  existing userspace WireGuard gateway.
- The sidecar needs pod-network privileges. The execution container
  should remain restricted.
- Enrollment is currently implemented only for WireGuard.
