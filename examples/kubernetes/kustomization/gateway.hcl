# Canonical dynamic-peer gateway config — the maintained example for the
# Kubernetes WireGuard setup. The base kustomization mounts this verbatim as
# the clawpatrol-config ConfigMap (configMapGenerator), so this file is the
# single source of truth: what CI validates (`clawpatrol validate`) is what
# gets deployed. It is also a complete, standalone config you can run with
# `clawpatrol gateway examples/kubernetes/kustomization/gateway.hcl`.
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
