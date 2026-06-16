# WireGuard dynamic peers for Kubernetes agent pods.
#
# The gateway runs the userspace WireGuard server. Agent pods run a
# privileged native sidecar init container running `clawpatrol run --tun`
# that self-registers with the `kubernetes_token_review` authorizer while
# the execution container stays restricted.

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
