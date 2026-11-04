package main

import (
	"context"
	"net"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	client "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	relay "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
)

func requireIPv6(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	ln.Close()
}
func ipv6Node(t *testing.T, kind string) *Node {
	t.Helper()
	dir := t.TempDir()
	key, err := loadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	opts := []libp2p.Option{libp2p.Identity(key), libp2p.NoTransports, libp2p.Security(noise.ID, noise.New), libp2p.EnableRelay(), libp2p.ForceReachabilityPublic()}
	switch kind {
	case "ws":
		opts = append(opts, libp2p.Transport(websocket.New), libp2p.ListenAddrStrings("/ip6/::1/tcp/0/ws"))
	case "tcp":
		opts = append(opts, libp2p.Transport(tcp.NewTCPTransport), libp2p.ListenAddrStrings("/ip6/::1/tcp/0"))
	case "quic":
		opts = append(opts, libp2p.Transport(quic.NewTransport), libp2p.ListenAddrStrings("/ip6/::1/udp/0/quic-v1"))
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	n := &Node{h: h, key: key, dir: dir, routes: map[peer.ID]Route{}, sendWake: make(chan struct{}, 1), sem: make(chan struct{}, 64)}
	h.SetStreamHandler(directoryProtocol, n.bounded(n.handleDirectory))
	h.SetStreamHandler(messageProtocol, n.bounded(n.handleMessage))
	return n
}
func TestIPv6DirectDelivery(t *testing.T) {
	requireIPv6(t)
	for _, kind := range []string{"ws", "tcp", "quic"} {
		t.Run(kind, func(t *testing.T) {
			a, b := ipv6Node(t, kind), ipv6Node(t, kind)
			connectTest(t, a, b)
			if _, err := a.queue(b.h.ID().String(), "Доставка по IPv6: "+kind); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := a.deliver(ctx, a.state.Messages[0].Message); err != nil {
				t.Fatal(err)
			}
			conns := a.h.Network().ConnsToPeer(b.h.ID())
			if len(conns) == 0 {
				t.Fatal("no connection")
			}
			if _, err := conns[0].RemoteMultiaddr().ValueForProtocol(ma.P_IP6); err != nil {
				t.Fatal("connection did not use IPv6")
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			if len(b.state.Messages) != 1 {
				t.Fatal("IPv6 message missing")
			}
		})
	}
}
func TestIPv6CircuitRelay(t *testing.T) {
	requireIPv6(t)
	hub, a, b := ipv6Node(t, "ws"), ipv6Node(t, "ws"), ipv6Node(t, "ws")
	service, err := relay.New(hub.h)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	connectTest(t, a, hub)
	connectTest(t, b, hub)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ai := peer.AddrInfo{ID: hub.h.ID(), Addrs: hub.h.Addrs()}
	if _, err = client.Reserve(ctx, b.h, ai); err != nil {
		t.Fatal(err)
	}
	r, err := b.localRoute()
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Addresses = []string{hub.h.Addrs()[0].String() + "/p2p/" + hub.h.ID().String() + "/p2p-circuit"}
	r.Signature, _ = b.key.Sign(bytesOf(r.Body))
	if err = hub.remember(r); err != nil {
		t.Fatal(err)
	}
	a.boots = []peer.AddrInfo{ai}
	if _, err = a.queue(b.h.ID().String(), "Через реле по IPv6"); err != nil {
		t.Fatal(err)
	}
	if err = a.deliver(ctx, a.state.Messages[0].Message); err != nil {
		t.Fatal(err)
	}
	conns := a.h.Network().ConnsToPeer(b.h.ID())
	if len(conns) == 0 || !conns[0].Stat().Limited {
		t.Fatal("relay was not used")
	}
	if _, err = conns[0].RemoteMultiaddr().ValueForProtocol(ma.P_IP6); err != nil {
		t.Fatal("relay path does not contain IPv6")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.state.Messages) != 1 {
		t.Fatal("IPv6 relayed message missing")
	}
}
