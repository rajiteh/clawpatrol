//go:build linux

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// The egress filter makes the pod fail closed even where the CNI leaves link
// or subnet routes in the main table: a packet may leave only through the
// tunnel, on loopback, as the bridge's own marked traffic, or as part of a
// connection that is already established (for example a reply to an inbound
// request). Optional reply routing runs before the filter. The table is the
// bridge's own, so it never changes other rules in the netns.
const bridgeNftTable = "clawpatrol"

// Packet directions from linux/netfilter/nf_conntrack_tuple_common.h.
const (
	ctDirOriginal = 0
	ctDirReply    = 1
)

type bridgeReplyRouting struct {
	cidr netip.Prefix
	dev  string
}

// egressFilterRules returns the output chain rules in order. The chain policy
// is drop. In nft syntax:
//
//	oifname "lo" accept
//	oifname "<iface>" accept
//	meta mark <mark> accept
//	ct state established,related accept
//	icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
func egressFilterRules(iface string, mark uint32) [][]expr.Any {
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	oifname := func(name string) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameData(name)},
			accept,
		}
	}
	icmpv6Type := func(typ byte) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{typ}},
			accept,
		}
	}
	return [][]expr.Any{
		oifname("lo"),
		oifname(iface),
		{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
			accept,
		},
		{
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			accept,
		},
		icmpv6Type(133), // router solicitation
		icmpv6Type(135), // neighbor solicitation
		icmpv6Type(136), // neighbor advertisement
	}
}

// ifnameData is an interface name as nftables compares it: NUL-padded to
// IFNAMSIZ.
func ifnameData(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return b
}

// applyEgressFilter replaces the bridge's table in one batch. Adding a table
// that exists is a no-op, so the delete in the same batch never fails.
func applyEgressFilter(c *nftables.Conn, iface string, mark uint32, reply bridgeReplyRouting) error {
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: bridgeNftTable}
	c.AddTable(t)
	c.DelTable(t)
	c.AddTable(t)
	policy := nftables.ChainPolicyDrop
	ch := c.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	for _, exprs := range egressFilterRules(iface, mark) {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: exprs})
	}
	if reply.cidr.IsValid() {
		addReplyRoutingChains(c, t, reply)
	}
	return c.Flush()
}

func installEgressFilter(iface string, mark int, reply bridgeReplyRouting) error {
	c, err := nftables.New()
	if err == nil {
		err = applyEgressFilter(c, iface, uint32(mark), reply)
	}
	if err != nil {
		if reply.cidr.IsValid() {
			return fmt.Errorf("load the nftables egress filter and reply routing: %w", err)
		}
		return fmt.Errorf("load the nftables egress filter (run with --egress-filter=off to start without it; see \"Runtime compatibility\" in the Kubernetes enrollment docs): %w", err)
	}
	return nil
}

// Leave the fail-closed filter and control-plane routes in place at shutdown.
func removeReplyRouting(iface string, mark int, cidr netip.Prefix) error {
	return errors.Join(
		runIP(replyRuleArgs("del", cidr, mark)...),
		installEgressFilter(iface, mark, bridgeReplyRouting{}),
	)
}

func addReplyRoutingChains(c *nftables.Conn, t *nftables.Table, reply bridgeReplyRouting) {
	input := c.AddChain(&nftables.Chain{
		Name: "reply_input", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityMangle,
	})
	output := c.AddChain(&nftables.Chain{
		Name: "reply_output", Table: t, Type: nftables.ChainTypeRoute,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle,
	})

	u32 := binaryutil.NativeEndian.PutUint32
	eq := func(b []byte) expr.Any { return &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b} }
	bitwise := func(mask, xor []byte) expr.Any {
		return &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: xor}
	}
	ct := func(key expr.CtKey) expr.Any { return &expr.Ct{Key: key, Register: 1} }
	ipv4 := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		eq([]byte{unix.NFPROTO_IPV4}),
	}
	cidrMatch := func(offset uint32) []expr.Any {
		addr := reply.cidr.Addr().As4()
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4},
			bitwise(binaryutil.BigEndian.PutUint32(^uint32(0)<<(32-reply.cidr.Bits())), u32(0)),
			eq(addr[:]),
		}
	}

	// INPUT sees locally delivered traffic, after conntrack has classified
	// it. Record the first direction and interface without changing verdicts
	// or disturbing the other bits in the connection mark.
	in := append(slices.Clone(ipv4), cidrMatch(12)...)
	in = append(in,
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, eq(ifnameData(reply.dev)),
		ct(expr.CtKeyDIRECTION), eq([]byte{ctDirOriginal}),
		ct(expr.CtKeySTATE), bitwise(u32(expr.CtStateBitNEW), u32(0)), eq(u32(expr.CtStateBitNEW)),
		ct(expr.CtKeyMARK), bitwise(u32(^uint32(bridgeReplyMark)), u32(bridgeReplyMark)),
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true},
	)
	c.AddRule(&nftables.Rule{Table: t, Chain: input, Exprs: in})

	// The route hook triggers another route lookup after changing the mark.
	// The usual output filter still evaluates the packet on its new path.
	out := append(ipv4, cidrMatch(16)...)
	out = append(out,
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1}, eq(u32(0)),
		ct(expr.CtKeyDIRECTION), eq([]byte{ctDirReply}),
		ct(expr.CtKeySTATE), bitwise(u32(expr.CtStateBitESTABLISHED), u32(0)), eq(u32(expr.CtStateBitESTABLISHED)),
		ct(expr.CtKeyMARK), bitwise(u32(bridgeReplyMark), u32(0)), eq(u32(bridgeReplyMark)),
		&expr.Immediate{Register: 1, Data: u32(bridgeReplyMark)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
	)
	c.AddRule(&nftables.Rule{Table: t, Chain: output, Exprs: out})
}
