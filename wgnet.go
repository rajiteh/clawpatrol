package main

// Embedded userspace WireGuard server. No kernel module, no wg-quick,
// no /etc/wireguard, no systemd. The clawall binary IS the WG endpoint.
//
// Lifecycle:
//   - StartWGServer parses Tailscale config block (control=wireguard),
//     boots a wireguard-go device backed by a netstack TUN. Peers are
//     added via AddPeer(pubkey, allowed-ip) from the onboarder.
//   - The netstack listener is exposed via Listen(addr) so the gateway
//     can serve TLS on the WG-side IP without ever touching the host's
//     kernel routing.
//
// Why netstack (not kernel /dev/net/tun): zero privilege requirements,
// works in LXC / OpenVZ / Docker / macOS, doesn't need NET_ADMIN. The
// "VPN" lives entirely inside this process.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func jsonUnmarshal(b []byte, v any) error      { return json.Unmarshal(b, v) }
func jsonMarshalIndent(v any) ([]byte, error)  { return json.MarshalIndent(v, "", "  ") }

func wgPubFromPrivHex(privHex string) (string, error) {
	priv, err := hex.DecodeString(strings.TrimSpace(privHex))
	if err != nil || len(priv) != 32 {
		return "", fmt.Errorf("invalid wg priv hex")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub), nil
}

type WGServer struct {
	tnet      *netstack.Net
	dev       *device.Device
	serverIP  netip.Addr
	publicKey string // hex-encoded, derived from the private key at boot
	peerFile  string
}

// StartWGServer brings up a userspace WG endpoint listening on
// 0.0.0.0:<ListenPort>. Server private key is read from disk; if
// missing, generated and persisted at <stateDir>/wg-server.key.
func StartWGServer(ts Tailscale, stateDir string) (*WGServer, error) {
	if ts.WGSubnetCIDR == "" {
		return nil, fmt.Errorf("wireguard: wg_subnet_cidr required")
	}
	listenPort := 51820
	if ts.WGEndpoint != "" {
		if _, p, err := net.SplitHostPort(ts.WGEndpoint); err == nil {
			fmt.Sscanf(p, "%d", &listenPort)
		}
	}

	// Server key: persisted hex-encoded so restarts keep the same pub.
	keyPath := stateDir + "/wg-server.key"
	priv, err := loadOrGenWGKey(keyPath)
	if err != nil {
		return nil, err
	}

	prefix, err := netip.ParsePrefix(ts.WGSubnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("wg subnet: %w", err)
	}
	serverIP := prefix.Addr().Next() // x.x.x.1

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{serverIP},
		[]netip.Addr{},
		1420,
	)
	if err != nil {
		return nil, fmt.Errorf("netstack tun: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelVerbose, "[wg] "))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", priv, listenPort)); err != nil {
		return nil, fmt.Errorf("wg ipc: %w", err)
	}
	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("wg up: %w", err)
	}
	pub, err := wgPubFromPrivHex(priv)
	if err != nil {
		return nil, fmt.Errorf("derive pub: %w", err)
	}
	srv := &WGServer{tnet: tnet, dev: dev, serverIP: serverIP, publicKey: pub, peerFile: stateDir + "/wg-peers.json"}
	// Replay persisted (pubkey → ip) pairs into the in-memory device
	// so reboots don't strand existing clients.
	for pubkey, ip := range loadPeers(srv.peerFile) {
		_ = dev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubkey, ip))
	}
	return srv, nil
}

func loadPeers(path string) map[string]string {
	out := map[string]string{}
	if b, err := os.ReadFile(path); err == nil {
		_ = jsonUnmarshal(b, &out)
	}
	return out
}

func savePeers(path string, peers map[string]string) error {
	b, _ := jsonMarshalIndent(peers)
	return os.WriteFile(path, b, 0o600)
}

// AddPeer registers a peer (after admin approval). Idempotent — same
// pubkey overwrites previous AllowedIPs. Persists the (pubkey → ip)
// mapping to disk so the gateway can replay registrations on restart;
// wireguard-go peers are in-memory only.
func (s *WGServer) AddPeer(pubkeyHex, peerIP string) error {
	if err := s.dev.IpcSet(fmt.Sprintf(
		"public_key=%s\nallowed_ip=%s/32\n",
		pubkeyHex, peerIP,
	)); err != nil {
		return err
	}
	peers := loadPeers(s.peerFile)
	peers[pubkeyHex] = peerIP
	return savePeers(s.peerFile, peers)
}

// Listen binds a TCP listener on the netstack interface — this is what
// the gateway accepts traffic from VPN peers on.
func (s *WGServer) Listen(addrPort string) (net.Listener, error) {
	host, portS, err := net.SplitHostPort(addrPort)
	if err != nil {
		return nil, err
	}
	if host == "" || host == "0.0.0.0" {
		host = s.serverIP.String()
	}
	addr, err := netip.ParseAddrPort(host + ":" + portS)
	if err != nil {
		return nil, err
	}
	return s.tnet.ListenTCPAddrPort(addr)
}

// PublicKey returns the server's WG pubkey (hex) — handed out to
// every onboarded client. wireguard-go's IpcGet exposes peer pubkeys
// (each [Peer] block starts with `public_key=`), NOT the server's
// own. We derive ours from the saved private key at boot.
func (s *WGServer) PublicKey() (string, error) {
	if s.publicKey == "" {
		return "", fmt.Errorf("server publicKey not initialized")
	}
	return s.publicKey, nil
}

func loadOrGenWGKey(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	// Generate a fresh X25519 private key. wireguard-go expects 64-char
	// lowercase hex (not base64) on the IPC channel.
	priv, err := wgGenPrivateHex()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(strings.TrimSuffix(path, "/wg-server.key"), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(priv), 0o600); err != nil {
		return "", err
	}
	return priv, nil
}
