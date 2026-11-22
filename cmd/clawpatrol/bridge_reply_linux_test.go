//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Run in a freshly created namespace:
// unshare -Urn env CLAWPATROL_NETNS_TEST=1 go test ./cmd/clawpatrol -run '^TestBridgeReplyRoutingInNetns$'
func TestBridgeReplyRoutingInNetns(t *testing.T) {
	if os.Getenv("CLAWPATROL_NETNS_TEST") != "1" {
		t.Skip("set CLAWPATROL_NETNS_TEST=1 in a throwaway network namespace")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	peer := exec.Command("sleep", "infinity")
	peer.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.Process.Kill()
		_ = peer.Wait()
	})
	pid := strconv.Itoa(peer.Process.Pid)
	peerRun := func(args ...string) string {
		t.Helper()
		return run(append([]string{"nsenter", "-t", pid, "-n", "--"}, args...)...)
	}
	const (
		underlay = "eth0"
		tunnel   = "clawpatrol0"
		gateway  = "10.47.0.1"
		client1  = "10.47.0.140"
		client2  = "10.47.0.141"
		client3  = "10.47.0.142"
		outside  = "192.0.2.10"
	)
	pod := "10.47.0.22"
	if addr := os.Getenv("CLAWPATROL_TEST_REPLY_POD"); addr != "" {
		pod = addr
	}
	addLink := func(local, remote string) {
		run("ip", "link", "add", local, "type", "veth", "peer", "name", remote, "netns", pid)
		run("ip", "link", "set", local, "up")
		peerRun("ip", "link", "set", remote, "up")
	}
	run("ip", "link", "set", "lo", "up")
	addLink(underlay, "cni")
	peerRun("ip", "addr", "add", gateway+"/32", "dev", "cni")
	for _, addr := range []string{client1, outside} {
		peerRun("ip", "addr", "add", addr+"/32", "dev", "cni")
	}
	run("ip", "addr", "add", pod+"/32", "dev", underlay)
	peerRun("ip", "route", "add", pod+"/32", "dev", "cni")
	run("ip", "route", "add", "default", "via", gateway, "dev", underlay, "onlink")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", tunnel).Run()
		_ = exec.Command("ip", "link", "del", underlay).Run()
		_ = exec.Command("ip", "-4", "rule", "del", "pref", bridgeRuleSuppressPref, "fwmark", "0x6f").Run()
		_ = exec.Command("ip", "-4", "rule", "del", "pref", bridgeRuleTablePref, "fwmark", "0x6f").Run()
		_ = exec.Command("ip", "-4", "rule", "del", "pref", "93", "fwmark", "0x888").Run()
	})

	setupTunnel := func() {
		addLink(tunnel, "wg")
		run("ip", "addr", "add", "10.55.0.2/32", "dev", tunnel)
		peerRun("ip", "addr", "add", client3+"/32", "dev", "wg")
		peerRun("ip", "route", "add", pod+"/32", "dev", "wg", "metric", "100")
	}
	setupTunnel()
	run("ip", "-4", "rule", "add", "pref", "93", "fwmark", "0x888", "lookup", "main")

	cidr := netip.MustParsePrefix("10.47.0.0/16")
	const mark = defaultBridgeFwmark
	install := func(wantSource string, enabled bool) {
		t.Helper()
		route, source, ok := discoverUnderlayRoute("-4", mark, tunnel)
		if !ok || source != wantSource || route != (linuxDefaultRoute{Dev: underlay, Via: gateway, OnLink: true}) {
			t.Fatalf("discovered underlay: %+v, %q, %v", route, source, ok)
		}
		if err := installUnderlayRouting(route, linuxDefaultRoute{}, false, mark, mark, defaultRouteProto); err != nil {
			t.Fatal(err)
		}
		reply := bridgeReplyRouting{}
		if enabled {
			reply = bridgeReplyRouting{cidr: cidr, dev: route.Dev}
			if err := ensureReplyRule(cidr, mark); err != nil {
				t.Fatal(err)
			}
		}
		if err := installEgressFilter(tunnel, mark, reply); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reply")
	})}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	get := func(client, dev string, wantOK bool) {
		t.Helper()
		url := fmt.Sprintf("http://%s:%d/", pod, ln.Addr().(*net.TCPAddr).Port)
		cmd := exec.Command("nsenter", "-t", pid, "-n", "--", bin, "-test.run=^TestBridgeReplyRoutingPeer$")
		cmd.Env = append(os.Environ(), "CLAWPATROL_TEST_REPLY_PEER="+dev+" "+client+" "+url)
		if out, err := cmd.CombinedOutput(); (err == nil) != wantOK {
			t.Fatalf("HTTP from %s on %s: expected success=%t, got %v\n%s", client, dev, wantOK, err, out)
		}
	}

	install("default", false)
	if err := replaceDefaultRoutes(tunnel, false); err != nil {
		t.Fatal(err)
	}
	get(client1, "cni", false)
	install("table", true)
	t.Cleanup(func() {
		if strings.Contains(run("ip", "-4", "rule", "show", "pref", bridgeReplyRulePref), "fwmark") {
			_ = removeReplyRouting(tunnel, mark, cidr)
		}
	})
	get(client1, "cni", true)
	peerRun("ip", "addr", "add", client2+"/32", "dev", "cni")
	get(client2, "cni", true)
	get(client3, "wg", true) // same CIDR, but original packets arrived through the tunnel
	get(outside, "cni", false)

	// An app-initiated send to the same CIDR still uses the tunnel. If a
	// more-specific CNI route exists, the fail-closed output filter denies it.
	if route := run("ip", "-4", "route", "get", client1); !strings.Contains(route, "dev "+tunnel) {
		t.Fatalf("app route to peer: %s", route)
	}
	send := func(marked bool) error {
		dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(pod)}}
		if marked {
			dialer.Control = markControl(mark)
		}
		c, err := dialer.DialContext(context.Background(), "udp4", net.JoinHostPort(client1, "9"))
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		_, err = c.Write([]byte("test"))
		return err
	}
	run("ip", "route", "add", client1+"/32", "via", gateway, "dev", underlay, "onlink")
	if err := send(false); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("app-initiated send on CNI route: %v, want EPERM", err)
	}
	if err := send(true); err != nil {
		t.Fatalf("control-plane send on CNI route: %v", err)
	}
	run("ip", "route", "del", client1+"/32")

	run("ip", "link", "del", tunnel)
	get(client1, "cni", false) // no initial route during the reconnect gap
	if err := send(false); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("app send without the tunnel: %v, want ENETUNREACH", err)
	}
	setupTunnel()
	install("table", true)
	if err := replaceDefaultRoutes(tunnel, false); err != nil {
		t.Fatal(err)
	}
	get(client1, "cni", true)
	get(client2, "cni", true)
	get(client3, "wg", true)

	if err := removeReplyRouting(tunnel, mark, cidr); err != nil {
		t.Fatal(err)
	}
	if got := run("ip", "-4", "rule", "show", "pref", bridgeReplyRulePref); got != "" {
		t.Fatalf("reply rule remains: %s", got)
	}
	if got := run("ip", "-4", "rule", "show", "pref", "93"); !strings.Contains(got, "fwmark 0x888") {
		t.Fatalf("unrelated rule missing: %s", got)
	}
	get(client1, "cni", false)
	get(client3, "wg", true)
}

// The client's device binding makes a reply received on the wrong veth fail
// the exchange, even though both veth peers live in the same namespace.
func TestBridgeReplyRoutingPeer(t *testing.T) {
	args := strings.Fields(os.Getenv("CLAWPATROL_TEST_REPLY_PEER"))
	if len(args) != 3 {
		t.Skip("helper for the isolated packet test")
	}
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(args[1])},
		Control: func(_, _ string, conn syscall.RawConn) error {
			var bindErr error
			err := conn.Control(func(fd uintptr) {
				bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, args[0])
			})
			return errors.Join(err, bindErr)
		},
	}
	client := &http.Client{
		Transport: &http.Transport{DialContext: dialer.DialContext},
		Timeout:   900 * time.Millisecond,
	}
	resp, err := client.Get(args[2])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "reply" {
		t.Fatalf("body = %q, err = %v", body, err)
	}
}
