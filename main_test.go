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

func TestConfigOverridesKeepSavedValues(t *testing.T) {
	dir := t.TempDir()
	saved := Config{Port: 8089, DirectPort: 4009, Bootstrap: "previous", Reachability: "private"}
	if err := atomicWrite(filepath.Join(dir, "config.json"), bytesOf(saved)); err != nil {
		t.Fatal(err)
	}
	cfg, err := savedConfig(dir, Config{Port: 8090}, map[string]bool{"port": true})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 8090 || cfg.DirectPort != 4009 || cfg.Bootstrap != "previous" || cfg.Reachability != "private" {
		t.Fatalf("settings lost: %+v", cfg)
	}
	cfg, err = savedConfig(dir, Config{Bootstrap: ""}, map[string]bool{"bootstrap": true})
	if err != nil || cfg.Bootstrap != "" {
		t.Fatal("explicit empty flag did not clear saved bootstrap", err)
	}
}
func TestRouteRefreshDoesNotRewriteHistory(t *testing.T) {
	n := testNode(t)
	if _, err := n.localRoute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(n.dir, "state.json")); !os.IsNotExist(err) {
		t.Fatal("address refresh unnecessarily wrote chat history")
	}
	raw, err := os.ReadFile(filepath.Join(n.dir, "sequence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var seq uint64
	if json.Unmarshal(raw, &seq) != nil || seq != n.state.Sequence {
		t.Fatal("routing counter was not persisted")
	}
}

func TestOfflinePeerDoesNotBlockOthersAndRecovers(t *testing.T) {
	a, offline, online := testNode(t), testNode(t), testNode(t)
	connectTest(t, a, online)
	if _, err := a.queue(offline.h.ID().String(), "Ждёт возвращения"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.queue(online.h.ID().String(), "Доступному собеседнику"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	done := make(chan struct{})
	go func() { defer close(done); a.sendLoop(ctx) }()
	defer func() { cancel(); <-done }()
	notify(a.sendWake)
	failed := false
	for ctx.Err() == nil {
		a.mu.Lock()
		d := a.delivery[offline.h.ID().String()]
		onlineDelivered := a.state.Messages[1].Status == "delivered"
		a.mu.Unlock()
		if d.Status == "unavailable" && onlineDelivered {
			if d.NextAttempt <= time.Now().UnixMilli() || d.Failures != 1 {
				t.Fatal("missing retry information")
			}
			failed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !failed {
		t.Fatal("offline recipient blocked another recipient or failure was not reported")
	}
	connectTest(t, a, offline)
	for ctx.Err() == nil {
		a.mu.Lock()
		delivered := a.state.Messages[0].Status == "delivered"
		d := a.delivery[offline.h.ID().String()]
		a.mu.Unlock()
		if delivered {
			if d.Status != "connected" || d.Failures != 0 || d.NextAttempt != 0 {
				t.Fatal("failure state was not cleared after recovery")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("message was not delivered after recipient became reachable")
}
func TestConnectionFailureAndRecipientRejection(t *testing.T) {
	t.Run("stale address", func(t *testing.T) {
		a, b := testNode(t), testNode(t)
		r, err := b.localRoute()
		if err != nil {
			t.Fatal(err)
		}
		if err = a.remember(r); err != nil {
			t.Fatal(err)
		}
		b.h.Close()
		_, err = a.queue(b.h.ID().String(), "Попытка на закрытый порт")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if a.deliver(ctx, a.state.Messages[0].Message) == nil {
			t.Fatal("closed recipient unexpectedly accepted message")
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		d := a.delivery[b.h.ID().String()]
		if d.Status != "connect_failed" || d.Detail == "" || d.NextAttempt == 0 {
			t.Fatalf("wrong failure state: %+v", d)
		}
	})
	t.Run("recipient refuses", func(t *testing.T) {
		a, b := testNode(t), testNode(t)
		connectTest(t, a, b)
		b.mu.Lock()
		b.state.Messages = make([]Entry, maxHistory)
		b.mu.Unlock()
		_, err := a.queue(b.h.ID().String(), "Нет места в истории получателя")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if a.deliver(ctx, a.state.Messages[0].Message) == nil {
			t.Fatal("rejection treated as successful delivery")
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.delivery[b.h.ID().String()].Status != "rejected" || a.state.Messages[0].Status != "queued" {
			t.Fatal("recipient rejection was not retained as pending")
		}
	})
}

func TestPastDeliveryDoesNotClaimPeerStillOnline(t *testing.T) {
	a, b := testNode(t), testNode(t)
	connectTest(t, a, b)
	if _, err := a.queue(b.h.ID().String(), "before disconnect"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.deliver(ctx, a.state.Messages[0].Message); err != nil {
		t.Fatal(err)
	}
	if a.snapshot().Peers[b.h.ID().String()].Status != "connected" {
		t.Fatal("live connection missing")
	}
	if err := a.h.Network().ClosePeer(b.h.ID()); err != nil {
		t.Fatal(err)
	}
	if a.snapshot().Peers[b.h.ID().String()].Status == "connected" {
		t.Fatal("past delivery incorrectly shown as online")
	}
}
