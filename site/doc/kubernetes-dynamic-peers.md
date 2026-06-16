# Kubernetes Dynamic Peers

Claw Patrol can run inside Kubernetes with one long-lived gateway pod
and stateless agent pods that appear only for the lifetime of a job.
The gateway still uses the WireGuard transport, but agent pods do not
need a pre-created peer or a human approval flow. Instead, each pod
self-registers as a short-lived **dynamic peer** using its projected
Kubernetes ServiceAccount token.

This mode is for same-cluster deployments where:

- the gateway runs in Kubernetes,
- agent pods are spawned on demand,
- the agent execution container must stay restricted,
- a privileged networking helper is acceptable outside the execution
  container.

The Kubernetes authorizer is currently supported only under
`gateway.wireguard.dynamic_peers`; Tailscale dynamic peers are not
implemented yet.

## Architecture

The deployment has three parts:

- **Gateway pod** — runs `clawpatrol gateway`, the dashboard/API, and
  the userspace WireGuard server. It needs Kubernetes API permission to
  create TokenReviews and read allowed agent pods.
- **WireGuard sidecar init container** — runs `clawpatrol run --tun`
  with `restartPolicy: Always`. It owns `/dev/net/tun`, `NET_ADMIN`,
  pod routing, the projected ServiceAccount token, dynamic peer
  registration, heartbeats, and deregistration.
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

Enable dynamic peers inside the WireGuard transport and add a named
`kubernetes_token_review` authorizer:

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

profile "default" {
  credentials = []
}
```

The authorizer verifies the pod's projected ServiceAccount token with
Kubernetes TokenReview, reads the live Pod object, checks namespace and
ServiceAccount against the allowlist, and selects the Claw Patrol
profile from the configured pod label. The client does not get to
submit its own profile.

The complete standalone HCL example lives at
[`examples/wireguard-dynamic-peers-kubernetes.hcl`](https://github.com/denoland/clawpatrol/blob/main/examples/wireguard-dynamic-peers-kubernetes.hcl).

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
      - run
      - --tun
      - --gateway-url=http://clawpatrol-api.clawpatrol.svc:8080
      - --dynamic-peer-authorizer=kubernetes_token_review/agents
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
- `get` on pods in namespaces that can run dynamic peer agents

The WireGuard endpoint in the example uses same-cluster Service DNS:

```hcl
endpoint = "clawpatrol-wg.clawpatrol.svc:51820"
```

## Lease lifecycle

On startup, the sidecar:

1. generates a WireGuard private key locally,
2. sends only the public key and Kubernetes pod claims to
   `POST /api/dynamic-peers/register`,
3. receives WireGuard client config, CA PEM, lease TTL, and a peer API
   token,
4. brings up the TUN device and routes pod traffic through it,
5. fetches env pushdown and writes `/clawpatrol/env`,
   `/clawpatrol/ca.crt`, and `/clawpatrol/ready`.

The sidecar heartbeats at half the lease TTL. On shutdown it sends a
best-effort deregistration request. If the pod disappears without
cleanup, the gateway expires the lease and revokes the transient
WireGuard peer.

## Local e2e

The repository includes a kind-based e2e flow that uses the same
Kustomize base plus an e2e overlay:

```bash
./e2e/kubernetes-wireguard-e2e.sh
```

The test builds the current workspace image, loads it into kind,
applies the e2e overlay, waits for the agent handoff, verifies the
restricted agent contract, checks traffic through the tunnel, confirms
heartbeat behavior, and verifies peer cleanup.

## Limitations

- v1 assumes the gateway and agents run in the same Kubernetes cluster.
- v1 assumes a single active WireGuard gateway replica.
- The gateway does not need kernel WireGuard privileges; it runs the
  existing userspace WireGuard gateway.
- The sidecar needs pod-network privileges. The execution container
  should remain restricted.
- Dynamic peers are currently implemented only for WireGuard.
