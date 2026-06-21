# e2e gateway config. Same shape as the base example but scoped to the
# isolated *-e2e namespaces with a short peer TTL so the e2e exercises
# enrollment + liveness reaping quickly. The overlay mounts this in place
# of the base config via a configMapGenerator with `behavior: replace`.
gateway {
  dashboard_listen = "0.0.0.0:8080"
  state_dir        = "/opt/clawpatrol"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
    listen_port = 51820
    endpoint    = "clawpatrol-wg.clawpatrol-e2e.svc:51820"
  }

  enrollment {
    peer_ttl = "30s"

    authorizer "kubernetes_token_review" "agents" {
      audience      = "clawpatrol"
      profile_label = "clawpatrol.dev/profile"

      allow {
        namespace       = "agents-e2e"
        service_account = "agent-runner"
        profiles        = ["default"]
      }
    }
  }
}

profile "default" {
  credentials = []
}
