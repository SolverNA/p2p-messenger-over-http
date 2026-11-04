package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	client "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	relay "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
)

func testNode(t *testing.T) *Node {
	t.Helper()
	dir := t.TempDir()
	key, err := loadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := libp2p.New(libp2p.Identity(key), libp2p.NoTransports, libp2p.Transport(websocket.New), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0/ws"), libp2p.Security(noise.ID, noise.New), libp2p.EnableRelay(), libp2p.ForceReachabilityPublic())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	n := &Node{h: h, key: key, dir: dir, routes: map[peer.ID]Route{}, sendWake: make(chan struct{}, 1), sem: make(chan struct{}, 64)}
	h.SetStreamHandler(directoryProtocol, n.bounded(n.handleDirectory))
	h.SetStreamHandler(messageProtocol, n.bounded(n.handleMessage))
	return n
}
func connectTest(t *testing.T, a, b *Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.h.Connect(ctx, peer.AddrInfo{ID: b.h.ID(), Addrs: b.h.Addrs()}); err != nil {
		t.Fatal(err)
	}
}
func TestSignedRecordsAndIdentity(t *testing.T) {
	n := testNode(t)
	k, err := loadKey(n.dir)
	if err != nil || !k.Equals(n.key) {
		t.Fatal("identity changed", err)
	}
	r, err := n.localRoute()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = validateRoute(r); err != nil {
		t.Fatal(err)
	}
	original := r
	r.Body.Peer = testNode(t).h.ID().String()
	if _, err = validateRoute(r); err == nil {
		t.Fatal("forged identity accepted")
	}
	r = original
	r.Body.Addresses = []string{"/ip4/1.2.3.4/tcp/80/ws"}
	if _, err = validateRoute(r); err == nil {
		t.Fatal("tampered addresses accepted")
	}
	r = original
	r.Body.Expires = time.Now().Add(-time.Second).Unix()
	r.Signature, _ = n.key.Sign(bytesOf(r.Body))
	if _, err = validateRoute(r); err == nil {
		t.Fatal("expired record accepted")
	}
	other := testNode(t)
	if err = other.remember(original); err != nil {
		t.Fatal(err)
	}
	newer := original
	newer.Body.Sequence++
	newer.Signature, _ = n.key.Sign(bytesOf(newer.Body))
	if err = other.remember(newer); err != nil {
		t.Fatal(err)
	}
	_ = other.remember(original)
	if got := other.cached(n.h.ID()); got == nil || got.Body.Sequence != newer.Body.Sequence {
		t.Fatal("routing record rolled back")
	}
}
func TestDirectDeliveryAndDedup(t *testing.T) {
	a, b := testNode(t), testNode(t)
	connectTest(t, a, b)
	id, err := a.queue(b.h.ID().String(), "привет <script>alert(1)</script>")
	if err != nil {
		t.Fatal(err)
	}
	m := a.state.Messages[0].Message
	if err = validateMessage(m, a.h.ID(), b.h.ID()); err != nil {
		t.Fatal(err)
	}
	tampered := m
	tampered.Body.Text = "forged"
	if validateMessage(tampered, a.h.ID(), b.h.ID()) == nil {
		t.Fatal("forged message accepted")
	}
	if validateMessage(m, testNode(t).h.ID(), b.h.ID()) == nil {
		t.Fatal("wrong sender accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = a.deliver(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err = a.deliver(ctx, m); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.state.Messages) != 1 || b.state.Messages[0].Message.Body.ID != id {
		t.Fatal("duplicate delivery")
	}
	data, err := os.ReadFile(filepath.Join(b.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state DiskState
	if json.Unmarshal(data, &state) != nil || len(state.Messages) != 1 {
		t.Fatal("acknowledged before persistence")
	}
}
func TestRealCircuitRelayDelivery(t *testing.T) {
	hub, a, b := testNode(t), testNode(t), testNode(t)
	service, err := relay.New(hub.h)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	connectTest(t, a, hub)
	connectTest(t, b, hub)
	ai := peer.AddrInfo{ID: hub.h.ID(), Addrs: hub.h.Addrs()}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err = client.Reserve(ctx, b.h, ai); err != nil {
		t.Fatal(err)
	}
	r, err := b.localRoute()
	if err != nil {
		t.Fatal(err)
	}
	// The sender receives ONLY the relay address. A direct dial cannot pass.
	r.Body.Addresses = []string{hub.h.Addrs()[0].String() + "/p2p/" + hub.h.ID().String() + "/p2p-circuit"}
	r.Signature, _ = b.key.Sign(bytesOf(r.Body))
	if err = hub.remember(r); err != nil {
		t.Fatal(err)
	}
	a.boots = []peer.AddrInfo{ai}
	a.h.Peerstore().ClearAddrs(b.h.ID())
	a.h.Peerstore().AddAddrs(hub.h.ID(), hub.h.Addrs(), peerstore.PermanentAddrTTL)
	_, err = a.queue(b.h.ID().String(), "message through an untrusted relay")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.deliver(ctx, a.state.Messages[0].Message); err != nil {
		t.Fatal(err)
	}
	conns := a.h.Network().ConnsToPeer(b.h.ID())
	if len(conns) == 0 || !conns[0].Stat().Limited {
		t.Fatal("test did not use circuit relay")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.state.Messages) != 1 {
		t.Fatal("relayed message missing")
	}
	// A relay may look up a signed address but must never store plaintext chat.
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.state.Messages) != 0 {
		t.Fatal("relay received application plaintext")
	}
}
func TestDirectoryFederation(t *testing.T) {
	a, hub1, hub2, b := testNode(t), testNode(t), testNode(t), testNode(t)
	connectTest(t, a, hub1)
	connectTest(t, hub1, hub2)
	connectTest(t, b, hub2)
	route, err := b.localRoute()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err = b.rpc(ctx, hub2.h.ID(), Request{Op: "register", Record: &route}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.rpc(ctx, hub1.h.ID(), Request{Op: "register", Record: &route}); err == nil {
		t.Fatal("registration for another identity accepted")
	}
	a.boots = []peer.AddrInfo{{ID: hub1.h.ID(), Addrs: hub1.h.Addrs()}}
	if _, err = a.lookup(ctx, b.h.ID(), 1, ""); err != nil {
		t.Fatal(err)
	}
	// Confirm that the returned registration includes usable addresses.
	cached := a.cached(b.h.ID())
	if cached == nil {
		t.Fatal("lookup not cached")
	}
	for _, s := range cached.Body.Addresses {
		if _, err := ma.NewMultiaddr(s); err != nil {
			t.Fatal(err)
		}
	}
}
func TestPersistentOutbox(t *testing.T) {
	a, b := testNode(t), testNode(t)
	_, err := a.queue(b.h.ID().String(), "offline message")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(a.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state DiskState
	if err = json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Messages) != 1 || state.Messages[0].Status != "queued" {
		t.Fatal("outbox was not persisted")
	}
	connectTest(t, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { a.sendLoop(ctx); close(done) }()
	notify(a.sendWake)
	for ctx.Err() == nil {
		a.mu.Lock()
		status := a.state.Messages[0].Status
		a.mu.Unlock()
		if status == "delivered" {
			cancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	<-done
	t.Fatal("queued message was not delivered")
}
