package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

func uniqueExtraPorts(rules []Rule) []int {
	seen := map[int]bool{}
	var out []int
	for _, r := range rules {
		if r.Port == 0 || r.Port == 443 {
			continue
		}
		if seen[r.Port] {
			continue
		}
		seen[r.Port] = true
		out = append(out, r.Port)
	}
	return out
}

func ruleForPort(rules []Rule, port int) *Rule {
	for i := range rules {
		if rules[i].Port == port {
			return &rules[i]
		}
	}
	return nil
}

func (g *Gateway) servePorts() {
	host := splitHost(g.cfg.Listen)
	for _, port := range uniqueExtraPorts(g.rules) {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("listen %s: %v", addr, err)
			continue
		}
		log.Printf("port %d listening (%d-host rule)", port, countRulesOnPort(g.rules, port))
		go g.acceptRaw(ln, port)
	}
}

func (g *Gateway) acceptRaw(ln net.Listener, port int) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept :%d: %v", port, err)
			return
		}
		go g.handleRaw(c, port)
	}
}

func (g *Gateway) handleRaw(c net.Conn, port int) {
	defer c.Close()
	rule := ruleForPort(g.rules, port)
	if rule == nil {
		return
	}
	if rule.Action == "deny" {
		log.Printf("deny port %d host %s: %s", port, rule.Host, rule.Reason)
		return
	}
	upstream := rule.Host
	if rule.Upstream != "" {
		upstream = rule.Upstream
	}
	g.spliceTo(c, upstream, port)
}

func (g *Gateway) spliceTo(c net.Conn, host string, port int) {
	start := time.Now()
	up, err := g.dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		log.Printf("dial %s:%d: %v", host, port, err)
		g.sink.Emit(Event{Mode: "splice", Host: host, Action: "error", Reason: err.Error(), Ms: time.Since(start).Milliseconds()})
		return
	}
	defer up.Close()
	defer func() {
		g.sink.Emit(Event{Mode: "splice", Host: host, Action: "allow", Ms: time.Since(start).Milliseconds()})
	}()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, c)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(c, up)
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func splitHost(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return ""
}

func countRulesOnPort(rules []Rule, port int) int {
	n := 0
	for _, r := range rules {
		if r.Port == port {
			n++
		}
	}
	return n
}

var _ = fmt.Sprintf // reserved for protocol handlers
