package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestPeerListParsingAndPublicValidation(t *testing.T) {
	n := testNode(t)
	id := n.h.ID().String()
	raw := []byte("# comment\n/dns4/node.example.org/tcp/443/tls/ws/p2p/" + id + "\n/dns6/node.example.org/tcp/443/tls/ws/p2p/" + id + "\n/dns4/node.example.org/tcp/443/tls/ws/p2p/" + id + " # duplicate\n")
	peers, err := parsePeerList(raw, true)
	if err != nil || len(peers) != 1 || len(peers[0].Addrs) != 2 {
		t.Fatalf("IPv4/IPv6 merge failed: %+v %v", peers, err)
	}
	for _, address := range []string{
		"/ip4/127.0.0.1/tcp/80/ws/p2p/" + id,
		"/ip6/::1/tcp/80/ws/p2p/" + id,
		"/ip6/2001:db8::1/tcp/80/ws/p2p/" + id,
		"/dns4/localhost/tcp/80/ws/p2p/" + id,
		"/dns4/node.example.org/tcp/0/ws/p2p/" + id,
		"/dns4/node.example.org/tcp/80/p2p/" + id,
		"/dns4/node.example.org/tcp/80/ws",
		"/dns4/node.example.org/tcp/80/ws/p2p/" + id + "/p2p-circuit/p2p/" + id,
	} {
		if _, err := parsePeerList([]byte(address), true); err == nil {
			t.Errorf("accepted invalid community entry: %s", address)
		}
	}
	if _, err := parsePeerList([]byte("/ip6/::1/tcp/80/ws/p2p/"+id), false); err != nil {
		t.Fatal("custom local lists must support private test networks", err)
	}
	if _, err := parsePeerList([]byte(strings.Repeat("#", (64<<10)+1)), true); err == nil {
		t.Fatal("accepted oversized list")
	}
}

func TestRepositoryPeerListIsValid(t *testing.T) {
	raw, err := os.ReadFile("public-peers.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePeerList(raw, true); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryConfigurationKeepsManualNetworksIsolated(t *testing.T) {
	if peerListSource(Config{}) != defaultPeerList {
		t.Fatal("default list disabled")
	}
	if peerListSource(Config{Bootstrap: "manual"}) != "" {
		t.Fatal("manual network contacted community registry")
	}
	if peerListSource(Config{PeerList: "off"}) != "" {
		t.Fatal("off ignored")
	}
	if peerListSource(Config{Bootstrap: "manual", PeerList: defaultPeerList}) != defaultPeerList {
		t.Fatal("explicit list ignored")
	}
	dir := t.TempDir()
	if err := atomicWrite(filepath.Join(dir, "config.json"), bytesOf(Config{PeerList: "my-peers.txt"})); err != nil {
		t.Fatal(err)
	}
	cfg, err := savedConfig(dir, Config{}, map[string]bool{})
	if err != nil || cfg.PeerList != "my-peers.txt" {
		t.Fatal("source not persisted", err)
	}
	cfg, err = savedConfig(dir, Config{PeerList: "off"}, map[string]bool{"peer-list": true})
	if err != nil || cfg.PeerList != "off" {
		t.Fatal("source override ignored", err)
	}
}

func TestPeerListHTTPFailureAndSizeLimits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte("# empty valid registry\n"))
		case "/large":
			w.Write([]byte(strings.Repeat("x", (64<<10)+1)))
		case "/redirect":
			http.Redirect(w, r, "http://example.org/peers.txt", http.StatusFound)
		default:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	if _, err := readPeerList(context.Background(), server.URL+"/ok"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/large", "/redirect", "/failure"} {
		if _, err := readPeerList(context.Background(), server.URL+p); err == nil {
			t.Fatal("accepted", p)
		}
	}
	if _, err := readPeerList(context.Background(), "http://example.org/peers.txt"); err == nil {
		t.Fatal("non-loopback cleartext source accepted")
	}
}

func TestDiscoverySelectsThreeAndReplacesUnavailablePeer(t *testing.T) {
	n := testNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	a, b, c, d := testNode(t), testNode(t), testNode(t), testNode(t)
	info := func(n *Node) peer.AddrInfo { return peer.AddrInfo{ID: n.h.ID(), Addrs: n.h.Addrs()} }
	list := []peer.AddrInfo{info(a), info(b), info(c)}
	cursor := 0
	n.selectRegistryPeers(ctx, list, &cursor)
	if len(n.bootstrapPeers()) != 3 {
		t.Fatalf("expected 3 selected nodes: %+v", n.snapshot().Discovery)
	}
	if len(n.h.Network().Conns()) != 0 {
		t.Fatal("probe leaked connections into the real host")
	}
	b.h.Close()
	n.selectRegistryPeers(ctx, []peer.AddrInfo{info(a), list[1], info(c), info(d)}, &cursor)
	selected := n.bootstrapPeers()
	if len(selected) != 3 {
		t.Fatalf("replacement not selected: %+v", n.snapshot().Discovery)
	}
	for _, p := range selected {
		if p.ID == b.h.ID() {
			t.Fatal("offline peer remained selected")
		}
	}
}

func TestDiscoveryUsesLastGoodCacheWhenSourceFails(t *testing.T) {
	n, hub := testNode(t), testNode(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 503) }))
	defer server.Close()
	text := []byte(hub.h.Addrs()[0].String() + "/p2p/" + hub.h.ID().String() + "\n")
	if err := atomicWrite(filepath.Join(n.dir, "peer-list-cache.json"), bytesOf(struct {
		Source string `json:"source"`
		Text   []byte `json:"text"`
	}{server.URL, text})); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); n.discover(ctx, server.URL) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := n.snapshot().Discovery
		if len(s.Selected) == 1 {
			if !s.Cached || s.Error == "" {
				t.Fatalf("cache/error status lost: %+v", s)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("cached peer not selected after source failure")
}

func TestRegistryProbeRejectsWrongIdentity(t *testing.T) {
	a, b := testNode(t), testNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	measured, err := probePublicPeers(ctx, []peer.AddrInfo{{ID: b.h.ID(), Addrs: a.h.Addrs()}})
	if err != nil {
		t.Fatal(err)
	}
	if len(measured) != 0 {
		t.Fatal("accepted a different server key at a listed address")
	}
}

func TestPublicSelectionKeepsCommonAnchor(t *testing.T) {
	nodes := []*Node{testNode(t), testNode(t), testNode(t), testNode(t)}
	var candidates []measuredPeer
	for i, n := range nodes {
		candidates = append(candidates, measuredPeer{Info: peer.AddrInfo{ID: n.h.ID()}, RTT: time.Duration(i+1) * time.Millisecond})
	}
	// Make the common anchor deliberately slow; private clients still choose RTT.
	anchor := 0
	for i := range candidates {
		if candidates[i].Info.ID.String() < candidates[anchor].Info.ID.String() {
			anchor = i
		}
	}
	candidates[anchor].RTT = time.Second
	private := choosePublicPeers(append([]measuredPeer{}, candidates...), false)
	for _, p := range private {
		if p.Info.ID == candidates[anchor].Info.ID {
			t.Fatal("private node ignored lower RTT alternatives")
		}
	}
	public := choosePublicPeers(append([]measuredPeer{}, candidates...), true)
	if public[0].Info.ID != candidates[anchor].Info.ID {
		t.Fatal("public node lost its common anchor")
	}
}
