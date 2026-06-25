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

Enrollment is configured under a top-level `enrollment` block. The
Kubernetes authorizer ships in-tree; it requires a `wireguard` block
(the only transport in v1).

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

Add a top-level `enrollment` block with a named `kubernetes_token_review`
authorizer:

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

profile "default" {
  credentials = []
}
```

The authorizer verifies the pod's projected ServiceAccount token with
Kubernetes TokenReview, reads the live Pod object, checks namespace and
ServiceAccount against the allowlist, and selects the Claw Patrol
profile from the configured pod label. The client does not get to
submit its own profile.

`peer_ttl` is the liveness window the gateway enforces (default `3m`).

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

There is no application heartbeat. The gateway observes liveness from
the WireGuard device: persistent keepalive advances the peer's
`rx_bytes` roughly every 25s, and a peer whose `rx_bytes` stops
advancing past `peer_ttl` is reaped. A freshly enrolled peer gets a full
`peer_ttl` grace window first. On shutdown the sidecar best-effort
deregisters; either way the gateway revokes the transient WireGuard peer
and clears its enrolled `wg_peers` row.

Enrolled peers show up in the dashboard as regular devices — there is no
separate enrollment surface.

## Local e2e

The repository includes a kind-based e2e flow that uses the same
Kustomize base plus an e2e overlay:

```bash
./e2e/kubernetes-wireguard-e2e.sh
```

The test builds the current workspace image, loads it into kind,
applies the e2e overlay, waits for the agent handoff, verifies the
restricted agent contract, checks traffic through the tunnel, confirms
rx_bytes liveness holds a live peer past `peer_ttl`, and verifies peer
cleanup.

## Limitations

- v1 assumes the gateway and agents run in the same Kubernetes cluster.
- v1 assumes a single active WireGuard gateway replica.
- The gateway does not need kernel WireGuard privileges; it runs the
  existing userspace WireGuard gateway.
- The sidecar needs pod-network privileges. The execution container
  should remain restricted.
- Enrollment is currently implemented only for WireGuard.
