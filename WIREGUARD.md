# clawall — WireGuard mode

This branch makes WireGuard the primary control plane. No Tailscale
account, no kernel module, no `wg-quick` lifecycle on the gateway,
no systemd unit for the WG interface. The clawall binary IS the WG
endpoint.

## What works (verified end-to-end)

- Operator runs `clawall gateway -config gateway.yaml` with
  `tailscale.control: wireguard`. Binary boots an embedded
  wireguard-go device backed by a gVisor netstack TUN, listens on
  UDP 51820, exposes the dashboard + MITM TLS via the WG-side IP
  (10.55.0.1 by default).
- Server keypair persisted at `<oauth_dir>/wg-server.key` (private
  hex), pubkey derived via curve25519 at boot.
- Peer registrations persisted at `<oauth_dir>/wg-peers.json` and
  replayed on every restart so existing clients survive gateway
  redeploys.
- Client runs `clawall join --url http://<gw>:9080`. Single command
  installs `wireguard-tools` if needed, generates a fresh keypair
  server-side, allocates an IP from the configured subnet,
  registers the peer, runs `wg-quick up`, pins
  `api.anthropic.com` / `api.openai.com` / `chatgpt.com` / etc to
  the gateway WG-side IP via `/etc/hosts`, claims the WG IP for
  the operator's identity, writes the env shim into shell rc.
- Agents (`claude`, `gh`, `codex`) run unmodified — `eval
  "$(clawall env)"` exports the placeholder tokens + CA bundle.
  Outbound HTTPS to `api.anthropic.com` resolves to 10.55.0.1,
  routes through WG, gateway SNI-peeks, MITMs, injects real OAuth
  bearer, forwards to real upstream, response comes back through
  the tunnel.
- No exit-node trickery — `wg-quick`'s default fwmark setup keeps
  SSH alive on Linux clients (only non-marked traffic goes through
  the tunnel).

## What's still rough

- `clawall gateway init` subcommand doesn't exist yet — operator
  still has to write `gateway.yaml` by hand, scp the binary, run
  it. `scripts/deploy.sh` works but is the old hacky path.
- Dashboard auth in WG mode is bypassed (no tailnet identity).
  Operator should front the public dashboard port with their own
  auth (Cloudflare Access, basic auth proxy, etc) — or only expose
  it via the WG tunnel itself (10.55.0.1:9080 is reachable from
  every onboarded device).
- Multi-user identity in WG mode still relies on `admin_email` —
  every approved device gets attributed to the same operator.
  Real per-user auth needs an auth proxy that fills
  `X-Forwarded-User` / `X-Forwarded-Email` (~10 LoC to teach
  `ownerForCaller` to read those).
- No exit-node-style packet forwarding inside netstack — that's
  why we redirect at name resolution (`/etc/hosts`). Adding
  arbitrary destinations means editing /etc/hosts (or running
  `clawall env` again after adding hosts to the rule list).

## Operator setup (current)

```bash
# on the gateway VM
curl -fsSL https://littledivy.github.io/clawall/install.sh | sh

cat > /etc/clawall.yaml <<EOF
listen: "0.0.0.0:8443"
info_listen: "0.0.0.0:9080"
public_url: "http://your-gw.example.com:9080"
ca_dir: "/opt/clawall/ca"
log_path: "/opt/clawall/gateway.log"
oauth_dir: "/opt/clawall/oauth"
admin_email: "you@example.com"
integrations: [claude, codex, github]
tailscale:
  control: wireguard
  wg_endpoint: "your-gw.example.com:51820"
  wg_subnet_cidr: "10.55.0.0/24"
demo: false
rules: []
EOF

mkdir -p /opt/clawall
clawall init-ca /opt/clawall/ca

# open ports + run
iptables -I INPUT -p udp --dport 51820 -j ACCEPT
iptables -I INPUT -p tcp --dport 9080 -j ACCEPT
clawall gateway -config /etc/clawall.yaml
```

Connect Claude / GitHub / Codex via the dashboard at
`http://your-gw.example.com:9080`. Per-user OAuth credentials
land in `/opt/clawall/oauth/`.

## Client setup

```bash
curl -fsSL https://littledivy.github.io/clawall/install.sh | sh
clawall join --url http://your-gw.example.com:9080
# approve at the displayed URL, done — claude/gh/codex just work
```
