# WireGuard enrollment for Kubernetes agent pods.
#
# The gateway runs the userspace WireGuard server. Agent pods run a
# privileged native sidecar init container running `clawpatrol bridge`
# that self-enrolls through the `kubernetes_token_review` authorizer while
# the execution container stays restricted.

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

  # Liveness is derived: keepalive_interval × timeout_multiplier. A peer is
  # reaped after `timeout_multiplier` missed keepalives. Here: 60s × 3 = 3m.
  keepalive_interval = "60s"
  timeout_multiplier = 3
}

profile "default" {
  credentials = []
}
