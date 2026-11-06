// P2P messenger: a single executable with a terminal interface.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/gdamore/tcell/v2"
	"github.com/gofrs/flock"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

const (
	directoryProtocol protocol.ID = "/p2pmessenger/directory/1.0.0"
	messageProtocol   protocol.ID = "/p2pmessenger/message/1.0.0"
	maxFrame                      = 128 << 10
	maxHistory                    = 10000
	defaultPeerList               = "https://raw.githubusercontent.com/SolverNA/p2p-messenger-over-http/main/public-peers.txt"
	maxPublicPeers                = 128
)

type RouteBody struct {
	Domain    string   `json:"domain"`
	Peer      string   `json:"peer"`
	PublicKey []byte   `json:"public_key"`
	Addresses []string `json:"addresses"`
	Sequence  uint64   `json:"sequence"`
	Expires   int64    `json:"expires"`
}
type Route struct {
	Body      RouteBody `json:"body"`
	Signature []byte    `json:"signature"`
}
type MessageBody struct {
	Domain string `json:"domain"`
	ID     string `json:"id"`
	From   string `json:"from"`
	To     string `json:"to"`
	Text   string `json:"text"`
	Time   int64  `json:"time"`
}
type Message struct {
	Body      MessageBody `json:"body"`
	Signature []byte      `json:"signature"`
}
type Entry struct {
	Message Message `json:"message"`
	Status  string  `json:"status"`
	Error   string  `json:"error,omitempty"`
}
type DiskState struct {
	Sequence uint64  `json:"sequence"`
	Messages []Entry `json:"messages"`
}
type Request struct {
	Op     string `json:"op"`
	Peer   string `json:"peer,omitempty"`
	Hops   int    `json:"hops,omitempty"`
	Record *Route `json:"record,omitempty"`
}
type Response struct {
	Record *Route `json:"record,omitempty"`
	Error  string `json:"error,omitempty"`
}
type Ack struct {
	ID    string `json:"id"`
	Error string `json:"error,omitempty"`
}
type Node struct {
	h          host.Host
	key        crypto.PrivKey
	dir        string
	boots      []peer.AddrInfo
	discovered []peer.AddrInfo
	discovery  DiscoveryStatus
	mu         sync.Mutex
	state      DiskState
	routes     map[peer.ID]Route
	delivery   map[string]PeerDelivery
	reach      network.Reachability
	wake       chan struct{}
	sendWake   chan struct{}
	sem        chan struct{}
}

func bytesOf(v any) []byte { b, _ := json.Marshal(v); return b }
func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	// Windows cannot FlushFileBuffers on a read-only directory handle. The
	// temporary file itself has already been synced before replacing the target.
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func loadKey(dir string) (crypto.PrivKey, error) {
	path := filepath.Join(dir, "identity.key")
	b, err := os.ReadFile(path)
	if err == nil {
		return crypto.UnmarshalPrivateKey(b)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	k, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	b, err = crypto.MarshalPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return k, atomicWrite(path, b)
}

// Caller holds n.mu. A delivery is acknowledged only after this succeeds.
func (n *Node) saveLocked() error {
	return atomicWrite(filepath.Join(n.dir, "state.json"), bytesOf(n.state))
}
func notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
func (n *Node) localRoute() (Route, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	seq := uint64(time.Now().UnixNano())
	if seq <= n.state.Sequence {
		seq = n.state.Sequence + 1
	}
	n.state.Sequence = seq
	// Address refreshes should write a tiny counter, not rewrite the entire chat
	// history every 30 seconds. Keep reading the old counter for compatibility.
	if err := atomicWrite(filepath.Join(n.dir, "sequence.json"), bytesOf(seq)); err != nil {
		return Route{}, err
	}
	pub, err := crypto.MarshalPublicKey(n.key.GetPublic())
	if err != nil {
		return Route{}, err
	}
	r := Route{Body: RouteBody{Domain: "p2pmessenger-route-v1", Peer: n.h.ID().String(), PublicKey: pub, Sequence: seq, Expires: time.Now().Add(3 * time.Minute).Unix()}}
	for _, a := range n.h.Addrs() {
		r.Body.Addresses = append(r.Body.Addresses, a.String())
	}
	if len(r.Body.Addresses) > 32 {
		r.Body.Addresses = r.Body.Addresses[:32]
	}
	sort.Strings(r.Body.Addresses)
	r.Signature, err = n.key.Sign(bytesOf(r.Body))
	if err == nil {
		n.routes[n.h.ID()] = r
	}
	return r, err
}
func validateRoute(r Route) (peer.AddrInfo, error) {
	b := r.Body
	if b.Domain != "p2pmessenger-route-v1" || b.Sequence == 0 || b.Expires <= time.Now().Unix() || b.Expires > time.Now().Add(5*time.Minute).Unix() || len(b.Addresses) > 32 || len(b.Addresses) == 0 {
		return peer.AddrInfo{}, errors.New("invalid/expired routing record")
	}
	k, err := crypto.UnmarshalPublicKey(b.PublicKey)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	id, err := peer.IDFromPublicKey(k)
	if err != nil || id.String() != b.Peer {
		return peer.AddrInfo{}, errors.New("public key does not match Peer ID")
	}
	ok, err := k.Verify(bytesOf(b), r.Signature)
	if err != nil || !ok {
		return peer.AddrInfo{}, errors.New("invalid routing signature")
	}
	ai := peer.AddrInfo{ID: id}
	for _, s := range b.Addresses {
		if len(s) > 2048 {
			return ai, errors.New("address too long")
		}
		a, e := ma.NewMultiaddr(s)
		if e != nil {
			return ai, e
		}
		ai.Addrs = append(ai.Addrs, a)
	}
	return ai, nil
}
func (n *Node) remember(r Route) error {
	ai, err := validateRoute(r)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	old, exists := n.routes[ai.ID]
	if exists && old.Body.Sequence >= r.Body.Sequence {
		return nil
	}
	if len(n.routes) >= 10000 {
		for id, v := range n.routes {
			if v.Body.Expires <= time.Now().Unix() {
				delete(n.routes, id)
			}
		}
		if len(n.routes) >= 10000 {
			return errors.New("directory is full")
		}
	}
	n.routes[ai.ID] = r
	n.h.Peerstore().AddAddrs(ai.ID, ai.Addrs, time.Until(time.Unix(r.Body.Expires, 0)))
	return nil
}
func (n *Node) cached(id peer.ID) *Route {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, ok := n.routes[id]
	if !ok || r.Body.Expires <= time.Now().Unix() {
		return nil
	}
	return &r
}
func (n *Node) candidates(exclude peer.ID) []peer.ID {
	seen := map[peer.ID]bool{n.h.ID(): true, exclude: true}
	var out []peer.ID
	for _, b := range n.bootstrapPeers() {
		if !seen[b.ID] {
			out = append(out, b.ID)
			seen[b.ID] = true
		}
	}
	for _, id := range n.h.Network().Peers() {
		if len(out) >= 16 {
			break
		}
		if !seen[id] {
			out = append(out, id)
			seen[id] = true
		}
	}
	return out
}

// Manual bootstrap peers stay pinned. Discovery only supplies additional peers.
func (n *Node) bootstrapPeers() []peer.AddrInfo {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := append([]peer.AddrInfo{}, n.boots...)
	seen := map[peer.ID]bool{}
	for _, p := range out {
		seen[p.ID] = true
	}
	for _, p := range n.discovered {
		if !seen[p.ID] && len(out) < 16 {
			out = append(out, p)
			seen[p.ID] = true
		}
	}
	return out
}

type DiscoveryPeer struct {
	Peer      string  `json:"peer"`
	RTTMillis float64 `json:"rtt_ms"`
}
type DiscoveryStatus struct {
	Source     string          `json:"source,omitempty"`
	Candidates int             `json:"candidates"`
	Selected   []DiscoveryPeer `json:"selected"`
	Updated    int64           `json:"updated,omitempty"`
	Cached     bool            `json:"cached"`
	Error      string          `json:"error,omitempty"`
}

// One WS/WSS multiaddress per line. Multiple addresses for one key are merged.
func parsePeerList(raw []byte, publicOnly bool) ([]peer.AddrInfo, error) {
	if len(raw) > 64<<10 {
		return nil, errors.New("peer list exceeds 64 KiB")
	}
	byID := map[peer.ID]int{}
	var out []peer.AddrInfo
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 2048), 4096)
	line := 0
	for scanner.Scan() {
		line++
		s := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if s == "" {
			continue
		}
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			return nil, fmt.Errorf("peer list line %d: invalid multiaddress", line)
		}
		ai, err := peer.AddrInfoFromP2pAddr(a)
		if err != nil || len(ai.Addrs) != 1 {
			return nil, fmt.Errorf("peer list line %d: expected address ending in /p2p/PEER_ID", line)
		}
		ps := ai.Addrs[0].Protocols()
		validHost := len(ps) > 0 && (ps[0].Code == ma.P_IP4 || ps[0].Code == ma.P_IP6 || ps[0].Code == ma.P_DNS || ps[0].Code == ma.P_DNS4 || ps[0].Code == ma.P_DNS6)
		validTransport := (len(ps) == 3 && ps[1].Code == ma.P_TCP && (ps[2].Code == ma.P_WS || ps[2].Code == ma.P_WSS)) || (len(ps) == 4 && ps[1].Code == ma.P_TCP && ps[2].Code == ma.P_TLS && ps[3].Code == ma.P_WS)
		port, _ := ai.Addrs[0].ValueForProtocol(ma.P_TCP)
		if !validHost || !validTransport || port == "0" {
			return nil, fmt.Errorf("peer list line %d: expected direct WS/WSS address with nonzero port", line)
		}
		if publicOnly && !manet.IsPublicAddr(ai.Addrs[0]) {
			return nil, fmt.Errorf("peer list line %d: address must be publicly routable", line)
		}
		if index, ok := byID[ai.ID]; ok {
			duplicate := false
			for _, existing := range out[index].Addrs {
				if existing.Equal(ai.Addrs[0]) {
					duplicate = true
				}
			}
			if !duplicate {
				if len(out[index].Addrs) == 8 {
					return nil, fmt.Errorf("peer list line %d: at most 8 addresses per peer", line)
				}
				out[index].Addrs = append(out[index].Addrs, ai.Addrs[0])
			}
		} else {
			if len(out) == maxPublicPeers {
				return nil, errors.New("peer list exceeds 128 peers")
			}
			byID[ai.ID] = len(out)
			out = append(out, *ai)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("peer list: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, nil
}

func peerListSource(c Config) string {
	if c.PeerList == "off" {
		return ""
	}
	if c.PeerList == "" || c.PeerList == "auto" {
		if strings.TrimSpace(c.Bootstrap) != "" {
			return ""
		}
		return defaultPeerList
	}
	return c.PeerList
}

func readPeerList(ctx context.Context, source string) ([]byte, error) {
	var reader io.ReadCloser
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		checkURL := func(u *url.URL) error {
			ip := net.ParseIP(u.Hostname())
			if u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()))) {
				return errors.New("peer list URL must use HTTPS (HTTP is allowed only on loopback)")
			}
			return nil
		}
		u, err := url.Parse(source)
		if err != nil {
			return nil, err
		}
		if err = checkURL(u); err != nil {
			return nil, err
		}
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many peer list redirects")
			}
			return checkURL(req.URL)
		}}
		req, err := http.NewRequestWithContext(ctx, "GET", source, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("peer list HTTP status %d", resp.StatusCode)
		}
		reader = resp.Body
	} else {
		f, err := os.Open(source)
		if err != nil {
			return nil, err
		}
		reader = f
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<10 {
		return nil, errors.New("peer list exceeds 64 KiB")
	}
	return raw, nil
}

type measuredPeer struct {
	Info peer.AddrInfo
	RTT  time.Duration
}

func choosePublicPeers(measured []measuredPeer, public bool) []measuredPeer {
	sort.Slice(measured, func(i, j int) bool {
		if measured[i].RTT == measured[j].RTT {
			return measured[i].Info.ID.String() < measured[j].Info.ID.String()
		}
		return measured[i].RTT < measured[j].RTT
	})
	if public && len(measured) > 3 {
		// One common reachable anchor helps public nodes bridge latency regions.
		anchor := 0
		for i := range measured {
			if measured[i].Info.ID.String() < measured[anchor].Info.ID.String() {
				anchor = i
			}
		}
		p := measured[anchor]
		copy(measured[1:anchor+1], measured[:anchor])
		measured[0] = p
	}
	return measured[:min(3, len(measured))]
}

// Probes use a temporary dial-only identity. Unselected candidates never become
// connections of the real node and never receive its signed route from a probe.
func probePublicPeers(ctx context.Context, peers []peer.AddrInfo) ([]measuredPeer, error) {
	if len(peers) == 0 {
		return nil, nil
	}
	h, err := libp2p.New(libp2p.NoListenAddrs, libp2p.NoTransports, libp2p.Transport(websocket.New), libp2p.Security(noise.ID, noise.New), libp2p.DisableRelay(), libp2p.UserAgent("p2pmessenger-probe/0.2"))
	if err != nil {
		return nil, err
	}
	defer h.Close()
	var wg sync.WaitGroup
	results := make(chan measuredPeer, len(peers))
	sem := make(chan struct{}, 4)
	for _, ai := range peers {
		wg.Add(1)
		go func(ai peer.AddrInfo) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if h.Connect(c, ai) != nil {
				return
			}
			select {
			case result, ok := <-ping.Ping(c, h, ai.ID):
				if ok && result.Error == nil {
					results <- measuredPeer{ai, result.RTT}
				}
			case <-c.Done():
			}
			h.Network().ClosePeer(ai.ID)
		}(ai)
	}
	wg.Wait()
	close(results)
	var out []measuredPeer
	for p := range results {
		out = append(out, p)
	}
	return out, nil
}

func (n *Node) selectRegistryPeers(ctx context.Context, peers []peer.AddrInfo, cursor *int) {
	batch := map[peer.ID]peer.AddrInfo{}
	n.mu.Lock()
	for _, ai := range n.discovered {
		for _, current := range peers {
			if current.ID == ai.ID {
				batch[ai.ID] = current
			}
		}
	}
	public := n.reach == network.ReachabilityPublic
	n.mu.Unlock()
	// Revisit common anchors and rotate a bounded sample through the full list.
	for _, ai := range peers[:min(3, len(peers))] {
		batch[ai.ID] = ai
	}
	for i := 0; i < min(8, len(peers)); i++ {
		ai := peers[(*cursor+i)%len(peers)]
		batch[ai.ID] = ai
	}
	if len(peers) > 0 {
		*cursor = (*cursor + 8) % len(peers)
	}
	var candidates []peer.AddrInfo
	for id, ai := range batch {
		if id != n.h.ID() {
			candidates = append(candidates, ai)
		}
	}
	measured, err := probePublicPeers(ctx, candidates)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		n.mu.Lock()
		n.discovery.Error = err.Error()
		n.mu.Unlock()
		return
	}
	selected := choosePublicPeers(measured, public)
	n.mu.Lock()
	previous := n.discovered
	n.discovered = nil
	n.discovery.Selected = nil
	for _, p := range selected {
		n.discovered = append(n.discovered, p.Info)
		n.discovery.Selected = append(n.discovery.Selected, DiscoveryPeer{p.Info.ID.String(), float64(p.RTT) / float64(time.Millisecond)})
	}
	n.mu.Unlock()
	for _, old := range previous {
		keep := false
		for _, ai := range n.bootstrapPeers() {
			if ai.ID == old.ID {
				keep = true
			}
		}
		// Keep existing relays and conversations; a registry is not a blocklist.
		for _, a := range n.h.Addrs() {
			if strings.Contains(a.String(), "/p2p/"+old.ID.String()+"/p2p-circuit") {
				keep = true
			}
		}
		for _, c := range n.h.Network().ConnsToPeer(old.ID) {
			for _, s := range c.GetStreams() {
				if s.Protocol() == messageProtocol {
					keep = true
				}
			}
		}
		if !keep {
			n.h.Network().ClosePeer(old.ID)
		}
	}
	notify(n.wake)
}

func (n *Node) discover(ctx context.Context, source string) {
	// Explicit custom lists may describe a private test network. The community
	// registry must contain publicly routable addresses only, including in cache.
	publicOnly := source == defaultPeerList
	var cached struct {
		Source string `json:"source"`
		Text   []byte `json:"text"`
	}
	var peers []peer.AddrInfo
	cache := filepath.Join(n.dir, "peer-list-cache.json")
	if raw, err := os.ReadFile(cache); err == nil && json.Unmarshal(raw, &cached) == nil && cached.Source == source {
		if list, err := parsePeerList(cached.Text, publicOnly); err == nil {
			peers = list
		}
	}
	n.mu.Lock()
	n.discovery = DiscoveryStatus{Source: source, Candidates: len(peers), Cached: len(peers) > 0}
	n.mu.Unlock()
	refresh := time.Time{}
	cursor := 0
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		if !time.Now().Before(refresh) {
			raw, err := readPeerList(ctx, source)
			var list []peer.AddrInfo
			if err == nil {
				list, err = parsePeerList(raw, publicOnly)
			}
			n.mu.Lock()
			if err != nil {
				n.discovery.Error = err.Error()
				n.discovery.Cached = len(peers) > 0
				refresh = time.Now().Add(30 * time.Second)
			} else {
				peers = list
				n.discovery.Candidates = len(peers)
				n.discovery.Updated = time.Now().UnixMilli()
				n.discovery.Cached = false
				n.discovery.Error = ""
				refresh = time.Now().Add(5 * time.Minute)
			}
			n.mu.Unlock()
			if err == nil {
				cached.Source, cached.Text = source, raw
				if err := atomicWrite(cache, bytesOf(cached)); err != nil {
					log.Printf("peer list cache: %v", err)
				}
			}
		}
		n.selectRegistryPeers(ctx, peers, &cursor)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (n *Node) rpc(ctx context.Context, id peer.ID, req Request) (Response, error) {
	var res Response
	ctx = network.WithAllowLimitedConn(ctx, "directory via relay")
	s, err := n.h.NewStream(ctx, id, directoryProtocol)
	if err != nil {
		return res, err
	}
	defer s.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = s.SetDeadline(deadline)
	if err = json.NewEncoder(s).Encode(req); err != nil {
		_ = s.Reset()
		return res, err
	}
	if err = json.NewDecoder(io.LimitReader(s, maxFrame)).Decode(&res); err != nil {
		_ = s.Reset()
		return res, err
	}
	if res.Error != "" {
		return res, errors.New(res.Error)
	}
	return res, nil
}
func (n *Node) lookup(ctx context.Context, id peer.ID, hops int, exclude peer.ID) (*Route, error) {
	if r := n.cached(id); r != nil {
		return r, nil
	}
	if hops < 0 {
		return nil, errors.New("peer not found")
	}
	peers := n.candidates(exclude)
	// Parallel bounded lookup: one unreachable directory must not block the others.
	results := make(chan *Route, len(peers))
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, p := range peers {
		go func(p peer.ID) {
			res, err := n.rpc(child, p, Request{Op: "find", Peer: id.String(), Hops: hops})
			if err == nil && res.Record != nil && res.Record.Body.Peer == id.String() && n.remember(*res.Record) == nil {
				results <- n.cached(id)
			} else {
				results <- nil
			}
		}(p)
	}
	for range peers {
		select {
		case r := <-results:
			if r != nil {
				return r, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("peer not found; check bootstrap nodes and recipient availability")
}
func (n *Node) bounded(handler func(network.Stream)) func(network.Stream) {
	return func(s network.Stream) {
		select {
		case n.sem <- struct{}{}:
			defer func() { <-n.sem }()
			handler(s)
		default:
			_ = s.Reset()
		}
	}
}
func (n *Node) handleDirectory(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(8 * time.Second))
	var q Request
	if err := json.NewDecoder(io.LimitReader(s, maxFrame)).Decode(&q); err != nil {
		_ = s.Reset()
		return
	}
	var res Response
	switch q.Op {
	case "register":
		if q.Record == nil || q.Record.Body.Peer != s.Conn().RemotePeer().String() {
			res.Error = "registration identity mismatch"
		} else if err := n.remember(*q.Record); err != nil {
			res.Error = err.Error()
		}
	case "find":
		id, err := peer.Decode(q.Peer)
		if err != nil || q.Hops < 0 || q.Hops > 1 {
			res.Error = "invalid lookup"
			break
		}
		res.Record = n.cached(id)
		if res.Record == nil && q.Hops > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			res.Record, _ = n.lookup(ctx, id, 0, s.Conn().RemotePeer())
			cancel()
		}
	default:
		res.Error = "unknown operation"
	}
	_ = json.NewEncoder(s).Encode(res)
}
func validateMessage(m Message, remote peer.ID, self peer.ID) error {
	b := m.Body
	if b.Domain != "p2pmessenger-message-v1" || b.From != remote.String() || b.To != self.String() || len(b.Text) == 0 || len(b.Text) > 16000 || len(b.ID) != 32 {
		return errors.New("invalid message")
	}
	if _, err := hex.DecodeString(b.ID); err != nil {
		return err
	}
	k, err := remote.ExtractPublicKey()
	if err != nil {
		return err
	}
	ok, err := k.Verify(bytesOf(b), m.Signature)
	if err != nil || !ok {
		return errors.New("invalid message signature")
	}
	return nil
}
func (n *Node) handleMessage(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(12 * time.Second))
	var m Message
	if err := json.NewDecoder(io.LimitReader(s, maxFrame)).Decode(&m); err != nil {
		_ = s.Reset()
		return
	}
	ack := Ack{ID: m.Body.ID}
	if err := validateMessage(m, s.Conn().RemotePeer(), n.h.ID()); err != nil {
		ack.Error = err.Error()
	} else {
		n.mu.Lock()
		found := false
		for _, e := range n.state.Messages {
			if e.Status == "received" && e.Message.Body.From == m.Body.From && e.Message.Body.ID == m.Body.ID {
				found = true
				if string(bytesOf(e.Message)) != string(bytesOf(m)) {
					ack.Error = "message ID collision"
				}
				break
			}
		}
		if !found {
			if len(n.state.Messages) >= maxHistory {
				ack.Error = "recipient history is full"
			} else {
				n.state.Messages = append(n.state.Messages, Entry{Message: m, Status: "received"})
				if err := n.saveLocked(); err != nil {
					n.state.Messages = n.state.Messages[:len(n.state.Messages)-1]
					ack.Error = "cannot persist message"
					log.Print(err)
				}
			}
		}
		n.mu.Unlock()
		if !found && ack.Error == "" {
			log.Printf("message from %s: %s", m.Body.From, m.Body.ID)
		}
	}
	_ = json.NewEncoder(s).Encode(ack)
}
func (n *Node) queue(to, text string) (string, error) {
	id, err := peer.Decode(strings.TrimSpace(to))
	if err != nil {
		return "", errors.New("invalid recipient Peer ID")
	}
	if id == n.h.ID() {
		return "", errors.New("choose another peer")
	}
	if _, err = id.ExtractPublicKey(); err != nil {
		return "", errors.New("recipient must have an inline Ed25519 public key")
	}
	if len(strings.TrimSpace(text)) == 0 || len(text) > 16000 {
		return "", errors.New("message must contain 1–16000 bytes")
	}
	m := Message{Body: MessageBody{Domain: "p2pmessenger-message-v1", ID: randomID(), From: n.h.ID().String(), To: id.String(), Text: text, Time: time.Now().UnixMilli()}}
	m.Signature, err = n.key.Sign(bytesOf(m.Body))
	if err != nil {
		return "", err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.state.Messages) >= maxHistory {
		return "", errors.New("history is full")
	}
	pending := 0
	for _, e := range n.state.Messages {
		if e.Status == "queued" {
			pending++
		}
	}
	if pending >= 1000 {
		return "", errors.New("outbox is full")
	}
	n.state.Messages = append(n.state.Messages, Entry{Message: m, Status: "queued"})
	if err = n.saveLocked(); err != nil {
		n.state.Messages = n.state.Messages[:len(n.state.Messages)-1]
		return "", err
	}
	notify(n.sendWake)
	return m.Body.ID, nil
}
func (n *Node) deliver(ctx context.Context, m Message) (result error) {
	id, err := peer.Decode(m.Body.To)
	if err != nil {
		return err
	}
	phase := "looking_up"
	n.deliveryPhase(m.Body.To, phase)
	defer func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		d := n.delivery[m.Body.To]
		if result != nil {
			// Refetch registration on retry, including after a network change.
			delete(n.routes, id)
			d.Failures++
			d.Status = map[string]string{"looking_up": "unavailable", "connecting": "connect_failed", "sending": "delivery_failed", "rejected": "rejected"}[phase]
			d.Detail = result.Error()
			d.NextAttempt = time.Now().Add(retryDelay(d.Failures)).UnixMilli()
		} else {
			d = PeerDelivery{Status: "connected"}
		}
		n.delivery[m.Body.To] = d
	}()
	// Refresh routing even when a stale direct address remains in the peerstore.
	if len(n.h.Network().ConnsToPeer(id)) == 0 {
		r, e := n.lookup(ctx, id, 1, "")
		if e != nil {
			return e
		}
		phase = "connecting"
		n.deliveryPhase(m.Body.To, phase)
		ai, e := validateRoute(*r)
		if e != nil {
			return e
		}
		// Give direct routes a brief first attempt, then permit circuit relay fallback.
		direct, cancel := context.WithTimeout(network.WithForceDirectDial(ctx, "prefer direct chat"), 3*time.Second)
		err = n.h.Connect(direct, ai)
		cancel()
		if err != nil {
			if err = n.h.Connect(ctx, ai); err != nil {
				return err
			}
		}
	}
	phase = "connecting"
	n.deliveryPhase(m.Body.To, phase)
	s, err := n.h.NewStream(network.WithAllowLimitedConn(ctx, "encrypted chat through relay"), id, messageProtocol)
	if err != nil {
		return err
	}
	defer s.Close()
	phase = "sending"
	n.deliveryPhase(m.Body.To, phase)
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = s.SetDeadline(deadline)
	stopCancel := context.AfterFunc(ctx, func() { _ = s.Reset() })
	defer stopCancel()
	if err = json.NewEncoder(s).Encode(m); err != nil {
		_ = s.Reset()
		return err
	}
	var ack Ack
	if err = json.NewDecoder(io.LimitReader(s, 4096)).Decode(&ack); err != nil {
		_ = s.Reset()
		return err
	}
	if ack.ID != m.Body.ID {
		return errors.New("invalid acknowledgement")
	}
	if ack.Error != "" {
		phase = "rejected"
		return errors.New(ack.Error)
	}
	return nil
}
func (n *Node) sendLoop(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-n.sendWake:
		}
		n.mu.Lock()
		var pending []Message
		for _, e := range n.state.Messages {
			if e.Status == "queued" && n.delivery[e.Message.Body.To].NextAttempt <= time.Now().UnixMilli() {
				pending = append(pending, e.Message)
			}
		}
		n.mu.Unlock()
		// Preserve per-recipient order, while allowing other recipients to progress.
		byPeer := map[string][]Message{}
		for _, m := range pending {
			byPeer[m.Body.To] = append(byPeer[m.Body.To], m)
		}
		slots := make(chan struct{}, 4)
		var wg sync.WaitGroup
		for _, list := range byPeer {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return
			}
			wg.Add(1)
			go func(list []Message) {
				defer wg.Done()
				defer func() { <-slots }()
				for _, m := range list {
					attempt, cancel := context.WithTimeout(ctx, 18*time.Second)
					err := n.deliver(attempt, m)
					cancel()
					n.mu.Lock()
					for i := range n.state.Messages {
						e := &n.state.Messages[i]
						if e.Message.Body.ID == m.Body.ID && e.Status == "queued" {
							old := *e
							if err == nil {
								e.Status = "delivered"
								e.Error = ""
							} else {
								e.Error = err.Error()
							}
							if e.Status != old.Status || e.Error != old.Error {
								if saveErr := n.saveLocked(); saveErr != nil {
									*e = old
									log.Print(saveErr)
								}
							}
							break
						}
					}
					n.mu.Unlock()
					if err != nil {
						break
					}
				}
			}(list)
		}
		wg.Wait()
	}
}
func (n *Node) publish(ctx context.Context) {
	r, err := n.localRoute()
	if err != nil {
		log.Printf("publish: %v", err)
		return
	}
	var wg sync.WaitGroup
	for _, p := range n.candidates("") {
		wg.Add(1)
		go func(p peer.ID) {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, _ = n.rpc(c, p, Request{Op: "register", Record: &r})
		}(p)
	}
	wg.Wait()
}
func (n *Node) maintain(ctx context.Context) {
	sub, err := n.h.EventBus().Subscribe([]interface{}{new(event.EvtLocalAddressesUpdated), new(event.EvtLocalReachabilityChanged), new(event.EvtPeerConnectednessChanged)})
	if err != nil {
		log.Print(err)
		return
	}
	defer sub.Close()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-sub.Out():
				if !ok {
					return
				}
				if r, ok := e.(event.EvtLocalReachabilityChanged); ok {
					n.mu.Lock()
					n.reach = r.Reachability
					n.mu.Unlock()
					log.Printf("reachability: %s", r.Reachability)
				}
				notify(n.wake)
			}
		}
	}()
	reconnect := time.NewTicker(5 * time.Second)
	defer reconnect.Stop()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	publish := time.NewTicker(30 * time.Second)
	defer publish.Stop()
	connect := func() {
		var wg sync.WaitGroup
		for _, b := range n.bootstrapPeers() {
			if len(n.h.Network().ConnsToPeer(b.ID)) > 0 {
				continue
			}
			wg.Add(1)
			go func(b peer.AddrInfo) {
				defer wg.Done()
				c, cancel := context.WithTimeout(ctx, 4*time.Second)
				defer cancel()
				if err := n.h.Connect(c, b); err != nil {
					log.Printf("bootstrap %s: %v", b.ID, err)
				}
			}(b)
		}
		wg.Wait()
	}
	connect()
	n.publish(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-reconnect.C:
			connect()
		case <-publish.C:
			n.publish(ctx)
		case <-n.wake:
			// Coalesce interface, relay address and connection changes.
			timer := time.NewTimer(300 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			connect()
			n.publish(ctx)
			notify(n.sendWake)
		case <-heartbeat.C:
			for _, p := range n.h.Network().Peers() {
				go func(p peer.ID) {
					c, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "keepalive"), 8*time.Second)
					defer cancel()
					select {
					case <-ping.Ping(c, n.h, p):
					case <-c.Done():
					}
				}(p)
			}
		}
	}
}

// Local control uses a private Unix socket, not a browser or an HTTP API.
type PeerDelivery struct {
	Status      string `json:"status"`
	Detail      string `json:"detail,omitempty"`
	Failures    int    `json:"failures,omitempty"`
	NextAttempt int64  `json:"next_attempt,omitempty"`
}

func retryDelay(failures int) time.Duration {
	return min(time.Minute, 5*time.Second<<min(4, max(0, failures-1)))
}
func (n *Node) deliveryPhase(id, phase string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.delivery == nil {
		n.delivery = map[string]PeerDelivery{}
	}
	d := n.delivery[id]
	d.Status = phase
	d.NextAttempt = 0
	n.delivery[id] = d
}
func peerDeliveryLabel(d PeerDelivery) string {
	label := map[string]string{"looking_up": "ищем собеседника", "connecting": "подключаемся", "sending": "отправляем", "connected": "на связи", "unavailable": "не в сети / недоступен", "connect_failed": "не удалось подключиться", "delivery_failed": "сбой доставки", "rejected": "получатель отклонил сообщение", "queued": "ожидает отправки"}[d.Status]
	if label == "" {
		label = "нет активного соединения"
	}
	if d.NextAttempt > 0 {
		seconds := max(int64(0), (d.NextAttempt-time.Now().UnixMilli()+999)/1000)
		label += fmt.Sprintf(" · повтор через %d с", seconds)
	}
	return label
}

type Connection struct {
	Peer    string `json:"peer"`
	Address string `json:"address"`
	Relay   bool   `json:"relay"`
}
type Snapshot struct {
	Peer         string                  `json:"peer"`
	Reachability string                  `json:"reachability"`
	Addresses    []string                `json:"addresses"`
	Connections  []Connection            `json:"connections"`
	Queued       int                     `json:"queued"`
	Messages     []Entry                 `json:"messages"`
	Peers        map[string]PeerDelivery `json:"peers"`
	Discovery    DiscoveryStatus         `json:"discovery"`
}
type ControlRequest struct {
	Op   string `json:"op"`
	To   string `json:"to,omitempty"`
	Text string `json:"text,omitempty"`
}
type ControlReply struct {
	State *Snapshot `json:"state,omitempty"`
	ID    string    `json:"id,omitempty"`
	Error string    `json:"error,omitempty"`
}

func (n *Node) snapshot() Snapshot {
	n.mu.Lock()
	s := Snapshot{Peer: n.h.ID().String(), Reachability: n.reach.String(), Messages: append([]Entry{}, n.state.Messages...), Peers: map[string]PeerDelivery{}, Discovery: n.discovery}
	s.Discovery.Selected = append([]DiscoveryPeer{}, n.discovery.Selected...)
	for id, d := range n.delivery {
		// A successful past delivery is not proof that the peer is still online.
		if d.Status != "connected" {
			s.Peers[id] = d
		}
	}
	n.mu.Unlock()
	for _, e := range s.Messages {
		if e.Status == "queued" {
			s.Queued++
			if _, ok := s.Peers[e.Message.Body.To]; !ok {
				s.Peers[e.Message.Body.To] = PeerDelivery{Status: "queued", Detail: e.Error}
			}
		}
	}
	for _, a := range n.h.Addrs() {
		s.Addresses = append(s.Addresses, a.String()+"/p2p/"+s.Peer)
	}
	for _, c := range n.h.Network().Conns() {
		s.Connections = append(s.Connections, Connection{c.RemotePeer().String(), c.RemoteMultiaddr().String(), c.Stat().Limited})
		if d, ok := s.Peers[c.RemotePeer().String()]; !ok || d.Status == "queued" {
			s.Peers[c.RemotePeer().String()] = PeerDelivery{Status: "connected"}
		}
	}
	return s
}
func controlCall(dir string, q ControlRequest) (ControlReply, error) {
	var reply ControlReply
	c, err := net.DialTimeout("unix", filepath.Join(dir, "control.sock"), 2*time.Second)
	if err != nil {
		return reply, fmt.Errorf("cannot connect to node: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err = json.NewEncoder(c).Encode(q); err == nil {
		err = json.NewDecoder(io.LimitReader(c, 512<<20)).Decode(&reply)
	}
	if err == nil && reply.Error != "" {
		err = errors.New(reply.Error)
	}
	return reply, err
}
func (n *Node) controlServer() (net.Listener, error) {
	path := filepath.Join(n.dir, "control.sock")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		ln.Close()
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case n.sem <- struct{}{}:
				go func() {
					defer c.Close()
					defer func() { <-n.sem }()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					var q ControlRequest
					if json.NewDecoder(io.LimitReader(c, maxFrame)).Decode(&q) != nil {
						return
					}
					var res ControlReply
					switch q.Op {
					case "snapshot":
						s := n.snapshot()
						res.State = &s
					case "send":
						id, err := n.queue(q.To, q.Text)
						res.ID = id
						if err != nil {
							res.Error = err.Error()
						}
					default:
						res.Error = "unknown local command"
					}
					_ = json.NewEncoder(c).Encode(res)
				}()
			default:
				c.Close()
			}
		}
	}()
	return ln, nil
}

type Config struct {
	Port         int    `json:"port"`
	DirectPort   int    `json:"direct_port"`
	Bootstrap    string `json:"bootstrap"`
	Announce     string `json:"announce"`
	Reachability string `json:"reachability"`
	TLSCert      string `json:"tls_cert"`
	TLSKey       string `json:"tls_key"`
	IPFamily     string `json:"ip_family"`
	PeerList     string `json:"peer_list"`
}

func listenAddresses(c Config, suffix string) ([]string, error) {
	family := c.IPFamily
	if family == "" {
		family = "auto"
	}
	var bases []string
	switch family {
	case "auto":
		bases = []string{"/ip4/0.0.0.0", "/ip6/::"}
	case "4":
		bases = []string{"/ip4/0.0.0.0"}
	case "6":
		bases = []string{"/ip6/::"}
	default:
		return nil, errors.New("--ip-family must be auto, 4 or 6")
	}
	var addrs []string
	for _, base := range bases {
		addrs = append(addrs, fmt.Sprintf("%s/tcp/%d/%s", base, c.Port, suffix))
		if c.DirectPort > 0 {
			addrs = append(addrs, fmt.Sprintf("%s/tcp/%d", base, c.DirectPort), fmt.Sprintf("%s/udp/%d/quic-v1", base, c.DirectPort))
		}
	}
	return addrs, nil
}

func defaultData() string {
	if base := os.Getenv("XDG_DATA_HOME"); base != "" {
		return filepath.Join(base, "p2pmessenger")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./node-data"
	}
	return filepath.Join(home, ".local", "share", "p2pmessenger")
}
func savedConfig(dir string, explicit Config, visited map[string]bool) (Config, error) {
	cfg := Config{Port: 8081, DirectPort: 4002, Reachability: "auto", IPFamily: "auto", PeerList: "auto"}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err == nil {
		if err = json.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("config.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return cfg, err
	}
	for name := range visited {
		switch name {
		case "port":
			cfg.Port = explicit.Port
		case "direct-port":
			cfg.DirectPort = explicit.DirectPort
		case "bootstrap":
			cfg.Bootstrap = explicit.Bootstrap
		case "announce":
			cfg.Announce = explicit.Announce
		case "reachability":
			cfg.Reachability = explicit.Reachability
		case "tls-cert":
			cfg.TLSCert = explicit.TLSCert
		case "tls-key":
			cfg.TLSKey = explicit.TLSKey
		case "ip-family":
			cfg.IPFamily = explicit.IPFamily
		case "peer-list":
			cfg.PeerList = explicit.PeerList
		}
	}
	return cfg, nil
}

// Strip terminal controls from remote text and escape tview style markup.
func terminalText(s string) string {
	return tview.Escape(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s))
}
func deliveryLabel(status string) string {
	switch status {
	case "queued":
		return "в очереди"
	case "delivered":
		return "доставлено"
	case "received":
		return "получено"
	}
	return status
}

type TerminalUI struct {
	app                           *tview.Application
	root                          *tview.Flex
	pages                         *tview.Pages
	header, history, notice, info *tview.TextView
	contacts                      *tview.List
	recipient                     *tview.InputField
	compose                       *tview.TextArea
	send                          *tview.Button
	active                        string
	peers                         []string
	lastHistory                   string
	lastContacts                  string
	state                         Snapshot
	request                       func(ControlRequest) (ControlReply, error)
	readClipboard                 func() (string, error)
	writeClipboard                func(string) error
	consoleSelection              func(bool) error
	mouseEnabled                  bool
}

// Windows installs native system clipboard functions from clipboard_windows.go.
// Other platforms keep terminal paste shortcuts and OSC 52 copying.
var nativeClipboardRead func() (string, error)
var nativeClipboardWrite func(string) error
var nativeConsoleSelection func(bool) error

func clipboardText(text string) string {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, text)
}

func (u *TerminalUI) copyText(text string) bool {
	if text == "" {
		u.notice.SetText("Нечего копировать")
		return false
	}
	if u.writeClipboard != nil {
		if err := u.writeClipboard(text); err != nil {
			u.notice.SetText("[red]Не удалось скопировать: " + terminalText(err.Error()) + "[-]")
			return false
		}
		u.notice.SetText("[green]Скопировано в системный буфер[-]")
	} else {
		fmt.Fprintf(os.Stdout, "\x1b]52;c;%s\a", base64.StdEncoding.EncodeToString([]byte(text)))
		u.notice.SetText("Текст передан терминалу для копирования (OSC 52)")
	}
	return true
}

func (u *TerminalUI) pasteClipboard() {
	if u.readClipboard == nil {
		u.notice.SetText("Используйте вставку терминала: Ctrl+Shift+V / Shift+Insert")
		return
	}
	text, err := u.readClipboard()
	if err != nil {
		u.notice.SetText("[red]Не удалось вставить: " + terminalText(err.Error()) + "[-]")
		return
	}
	text = clipboardText(text)
	if text == "" {
		u.notice.SetText("В буфере нет текста")
		return
	}
	if len(text) > 16000 {
		u.notice.SetText("[red]В буфере больше 16 000 байт; вставка отменена[-]")
		return
	}
	setFocus := func(p tview.Primitive) { u.app.SetFocus(p) }
	if u.recipient.HasFocus() {
		text = strings.TrimSpace(text)
		if strings.ContainsAny(text, "\n\t") {
			u.notice.SetText("[red]В поле «Кому» нужен один Peer ID[-]")
			return
		}
		u.recipient.PasteHandler()(text, setFocus)
	} else {
		_, start, end := u.compose.GetSelection()
		if len(u.compose.GetText())-(end-start)+len(text) > 16000 {
			u.notice.SetText("[red]Сообщение после вставки превышает 16 000 байт[-]")
			return
		}
		u.pages.RemovePage("copy")
		u.pages.HidePage("info")
		u.app.SetFocus(u.compose)
		u.compose.PasteHandler()(text, setFocus)
	}
	u.notice.SetText("[green]Вставлено. Enter: отправить; Alt+Enter: новая строка[-]")
}

func (u *TerminalUI) showCopyPicker() {
	type item struct{ label, text string }
	items := []item{{"Ваш Peer ID", u.state.Peer}}
	if u.active != "" {
		items = append(items, item{"Peer ID собеседника", u.active})
	}
	for _, entry := range u.state.Messages {
		b := entry.Message.Body
		if u.active == "" || b.From != u.active && b.To != u.active {
			continue
		}
		label := clipboardText(b.Text)
		label = strings.ReplaceAll(strings.ReplaceAll(label, "\n", " ↵ "), "\t", " ")
		runes := []rune(label)
		if len(runes) > 100 {
			label = string(runes[:100]) + "…"
		}
		name := "Собеседник"
		if b.From == u.state.Peer {
			name = "Вы"
		}
		items = append(items, item{time.UnixMilli(b.Time).Local().Format("15:04") + " · " + name + " · " + label, b.Text})
	}
	list := tview.NewList().ShowSecondaryText(false).SetUseStyleTags(false, false)
	list.SetBorder(true).SetTitle(" Копировать · ↑/↓ и Enter · Esc: назад ")
	for _, it := range items {
		list.AddItem(it.label, "", 0, nil)
	}
	closePicker := func() { u.pages.RemovePage("copy"); u.app.SetFocus(u.compose) }
	list.SetDoneFunc(closePicker)
	list.SetSelectedFunc(func(i int, _, _ string, _ rune) {
		if i >= 0 && i < len(items) {
			u.copyText(items[i].text)
			closePicker()
		}
	})
	u.pages.AddPage("copy", list, true, true)
	u.app.SetFocus(list)
}

func (u *TerminalUI) copyFocusedText(cut bool) {
	page, p := u.pages.GetFrontPage()
	if page == "copy" {
		p.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(p tview.Primitive) { u.app.SetFocus(p) })
		return
	}
	if u.recipient.HasFocus() {
		if u.copyText(u.recipient.GetText()) && cut {
			u.recipient.SetText("")
		}
		return
	}
	if u.compose.HasFocus() {
		text, _, _ := u.compose.GetSelection()
		if text == "" && !cut {
			text = u.compose.GetText()
		}
		if u.copyText(text) && cut {
			u.compose.PasteHandler()("", func(p tview.Primitive) { u.app.SetFocus(p) })
		}
		return
	}
	if page == "info" {
		u.copyText(u.info.GetText(true))
		return
	}
	u.showCopyPicker()
}

func (u *TerminalUI) toggleMouse() {
	u.mouseEnabled = !u.mouseEnabled
	u.app.EnableMouse(u.mouseEnabled)
	if u.consoleSelection != nil {
		if err := u.consoleSelection(!u.mouseEnabled); err != nil {
			u.notice.SetText("[yellow]Режим мыши переключён: " + terminalText(err.Error()) + "[-]")
			return
		}
	}
	if u.mouseEnabled {
		u.notice.SetText("Мышь управляет TUI. F5: копирование сообщений; F7: выделение терминала")
	} else {
		u.notice.SetText("Выделение терминала включено. Выделите мышью и скопируйте; Esc снимает выделение, F7 возвращает мышь TUI")
	}
}

func newTerminalUI(call func(ControlRequest) (ControlReply, error)) *TerminalUI {
	u := &TerminalUI{app: tview.NewApplication(), request: call, readClipboard: nativeClipboardRead, writeClipboard: nativeClipboardWrite, consoleSelection: nativeConsoleSelection, mouseEnabled: true}
	u.header = tview.NewTextView().SetDynamicColors(true)
	u.notice = tview.NewTextView().SetDynamicColors(true).SetText("Ctrl+C: копировать • F4: вставить • F5: сообщения • F3: свой ID • F7: мышь • F2: сеть • Ctrl+Q: выход")
	u.history = tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWordWrap(true)
	u.history.SetBorder(true).SetTitle(" Беседа ")
	u.info = tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWordWrap(true)
	u.info.SetBorder(true).SetTitle(" Узел и соединения · Esc/F2: закрыть ")
	u.contacts = tview.NewList().ShowSecondaryText(false).SetUseStyleTags(false, false)
	u.contacts.SetBorder(true).SetTitle(" Беседы ")
	u.recipient = tview.NewInputField().SetLabel("Кому: ").SetPlaceholder("Вставьте Peer ID и нажмите Enter")
	u.compose = tview.NewTextArea().SetPlaceholder("Сообщение…").SetMaxLength(16000)
	u.compose.SetBorder(true).SetTitle(" Сообщение · Enter: отправить · Alt+Enter: новая строка ")
	u.send = tview.NewButton("Отправить").SetSelectedFunc(u.sendMessage)
	u.contacts.SetSelectedFunc(func(i int, _, _ string, _ rune) {
		if i < len(u.peers) {
			u.selectPeer(u.peers[i])
		}
	})
	u.recipient.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			u.selectPeer(strings.TrimSpace(u.recipient.GetText()))
		}
	})
	u.compose.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		if e.Key() == tcell.KeyEnter {
			if e.Modifiers()&tcell.ModAlt != 0 {
				u.compose.PasteHandler()("\n", func(p tview.Primitive) { u.app.SetFocus(p) })
			} else {
				u.sendMessage()
			}
			return nil
		}
		return e
	})
	content := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(u.recipient, 1, 0, false).AddItem(u.history, 0, 1, false).AddItem(u.compose, 5, 0, true).AddItem(u.send, 1, 0, false)
	body := tview.NewFlex().AddItem(u.contacts, 24, 0, false).AddItem(content, 0, 1, true)
	u.root = tview.NewFlex().SetDirection(tview.FlexRow).AddItem(u.header, 3, 0, false).AddItem(body, 0, 1, true).AddItem(u.notice, 2, 0, false)
	u.pages = tview.NewPages().AddPage("chat", u.root, true, true).AddPage("info", u.info, true, false)
	focus := []tview.Primitive{u.recipient, u.contacts, u.history, u.compose, u.send}
	u.app.SetInputCapture(func(e *tcell.EventKey) *tcell.EventKey {
		if e.Key() == tcell.KeyInsert && e.Modifiers()&tcell.ModCtrl != 0 {
			u.copyFocusedText(false)
			return nil
		}
		if e.Key() == tcell.KeyInsert && e.Modifiers()&tcell.ModShift != 0 && u.readClipboard != nil {
			u.pasteClipboard()
			return nil
		}
		switch e.Key() {
		case tcell.KeyCtrlQ:
			u.app.Stop()
			return nil
		case tcell.KeyCtrlC:
			u.copyFocusedText(false)
			return nil
		case tcell.KeyCtrlX:
			if u.readClipboard != nil && (u.compose.HasFocus() || u.recipient.HasFocus()) {
				u.copyFocusedText(true)
				return nil
			}
		case tcell.KeyCtrlV:
			if u.readClipboard != nil {
				u.pasteClipboard()
				return nil
			}
		case tcell.KeyCtrlA:
			if u.compose.HasFocus() {
				u.compose.Select(0, len(u.compose.GetText()))
				return nil
			}
			if u.recipient.HasFocus() {
				u.recipient.InputHandler()(tcell.NewEventKey(tcell.KeyCtrlL, 0, tcell.ModNone), func(p tview.Primitive) { u.app.SetFocus(p) })
				return nil
			}
		case tcell.KeyF3:
			u.copyText(u.state.Peer)
			return nil
		case tcell.KeyF4:
			u.pasteClipboard()
			return nil
		case tcell.KeyF5:
			u.showCopyPicker()
			return nil
		case tcell.KeyF7:
			u.toggleMouse()
			return nil
		case tcell.KeyF2:
			u.pages.RemovePage("copy")
			u.app.SetFocus(u.compose)
			if u.pages.HasFocus() && u.pages.GetPageCount() > 0 {
				name, _ := u.pages.GetFrontPage()
				if name == "info" {
					u.pages.HidePage("info")
					u.app.SetFocus(u.compose)
				} else {
					u.pages.ShowPage("info")
					u.app.SetFocus(u.info)
				}
			}
			return nil
		case tcell.KeyEscape:
			u.pages.RemovePage("copy")
			u.pages.HidePage("info")
			u.app.SetFocus(u.compose)
			return nil
		case tcell.KeyCtrlS:
			u.sendMessage()
			return nil
		case tcell.KeyTab, tcell.KeyBacktab:
			name, _ := u.pages.GetFrontPage()
			if name == "info" || name == "copy" {
				return nil
			}
			for i, p := range focus {
				if p.HasFocus() {
					delta := 1
					if e.Key() == tcell.KeyBacktab {
						delta = len(focus) - 1
					}
					u.app.SetFocus(focus[(i+delta)%len(focus)])
					return nil
				}
			}
		}
		return e
	})
	u.app.SetRoot(u.pages, true).EnableMouse(true).EnablePaste(true).SetFocus(u.recipient)
	return u
}
func (u *TerminalUI) selectPeer(id string) {
	if _, err := peer.Decode(id); err != nil {
		u.notice.SetText("[red]Некорректный Peer ID[-]")
		return
	}
	if id == u.state.Peer {
		u.notice.SetText("[red]Выберите другого пира[-]")
		return
	}
	u.active = id
	u.recipient.SetText(id)
	u.lastHistory = ""
	u.update(u.state)
	u.app.SetFocus(u.compose)
}
func (u *TerminalUI) sendMessage() {
	to, text := strings.TrimSpace(u.recipient.GetText()), u.compose.GetText()
	if _, err := peer.Decode(to); err != nil {
		u.notice.SetText("[red]Введите Peer ID собеседника[-]")
		return
	}
	// Queueing is a local durable operation; it never waits for a network peer.
	res, err := u.request(ControlRequest{Op: "send", To: to, Text: text})
	if err != nil {
		u.notice.SetText("[red]" + terminalText(err.Error()) + "[-]")
		return
	}
	u.compose.SetText("", true)
	u.active = to
	u.lastHistory = ""
	u.notice.SetText("[green]В очереди: " + res.ID + "[-]")
}
func (u *TerminalUI) update(s Snapshot) {
	u.state = s
	role := map[string]string{"Public": "публичный", "Private": "за NAT", "Unknown": "определяем доступность"}[s.Reachability]
	u.header.SetText(fmt.Sprintf("[green]Связь / P2P[-] · %s · соединений %d · в очереди %d\nВаш Peer ID: %s", role, len(s.Connections), s.Queued, s.Peer))
	seen := map[string]bool{}
	var peers []string
	add := func(p string) {
		if p != "" && p != s.Peer && !seen[p] {
			seen[p] = true
			peers = append(peers, p)
		}
	}
	for i := len(s.Messages) - 1; i >= 0; i-- {
		b := s.Messages[i].Message.Body
		if b.From == s.Peer {
			add(b.To)
		} else {
			add(b.From)
		}
	}
	add(u.active)
	var labels []string
	for _, p := range peers {
		labels = append(labels, p+":"+s.Peers[p].Status)
	}
	key := strings.Join(labels, ",")
	if key != u.lastContacts {
		u.lastContacts = key
		current := u.contacts.GetCurrentItem()
		selected := ""
		if current >= 0 && current < len(u.peers) {
			selected = u.peers[current]
		}
		u.contacts.Clear()
		u.peers = peers
		for i, p := range peers {
			label := p
			if len(label) > 12 {
				label = label[len(label)-12:]
			}
			mark := "○ "
			if s.Peers[p].Status == "connected" {
				mark = "● "
			}
			u.contacts.AddItem(mark+label, "", 0, nil)
			if p == selected {
				current = i
			}
		}
		if current < len(peers) {
			u.contacts.SetCurrentItem(current)
		}
	}
	var chat strings.Builder
	if u.active != "" {
		u.history.SetTitle(" Беседа · " + peerDeliveryLabel(s.Peers[u.active]) + " ")
	}
	for _, e := range s.Messages {
		b := e.Message.Body
		if b.From != u.active && b.To != u.active {
			continue
		}
		name := "Собеседник"
		color := "white"
		if b.From == s.Peer {
			name = "Вы"
			color = "green"
		}
		fmt.Fprintf(&chat, "[%s]%s · %s · %s[-]\n%s\n", color, name, time.UnixMilli(b.Time).Local().Format("02.01 15:04:05"), deliveryLabel(e.Status), terminalText(b.Text))
		if e.Error != "" {
			fmt.Fprintln(&chat, "[yellow]Не доставлено. Сообщение сохранено; повторим автоматически. Причина — F2.[-]")
		}
		chat.WriteByte('\n')
	}
	text := chat.String()
	if text == "" {
		text = "Выберите беседу или вставьте Peer ID в поле «Кому»."
	}
	if text != u.lastHistory {
		u.lastHistory = text
		u.history.SetText(text).ScrollToEnd()
	}
	var info strings.Builder
	if s.Discovery.Source != "" {
		fmt.Fprintf(&info, "[green]Публичные узлы из списка[-]\n%s\nИзвестно: %d · выбрано: %d\n", terminalText(s.Discovery.Source), s.Discovery.Candidates, len(s.Discovery.Selected))
		if s.Discovery.Cached {
			info.WriteString("Используется сохранённая копия списка.\n")
		}
		if s.Discovery.Error != "" {
			fmt.Fprintf(&info, "[yellow]%s[-]\n", terminalText(s.Discovery.Error))
		}
		if s.Discovery.Candidates == 0 {
			info.WriteString("Список пуст или ещё не загружен; можно задать --bootstrap.\n")
		}
		for _, p := range s.Discovery.Selected {
			fmt.Fprintf(&info, "%s · RTT %.1f мс\n", terminalText(p.Peer), p.RTTMillis)
		}
		info.WriteString("\n")
	}
	fmt.Fprintf(&info, "[green]Ваш Peer ID[-]\n%s\n\n[green]Адреса[-]\n%s\n\n[green]Соединения[-]\n", terminalText(s.Peer), terminalText(strings.Join(s.Addresses, "\n")))
	for _, c := range s.Connections {
		kind := "прямое"
		if c.Relay {
			kind = "реле"
		}
		fmt.Fprintf(&info, "%s\n%s · %s\n\n", terminalText(c.Peer), kind, terminalText(c.Address))
	}
	info.WriteString("\n[green]Доставка собеседникам[-]\n")
	ids := make([]string, 0, len(s.Peers))
	for id := range s.Peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := s.Peers[id]
		fmt.Fprintf(&info, "%s\n%s\n%s\n\n", terminalText(id), peerDeliveryLabel(d), terminalText(d.Detail))
	}
	u.info.SetText(info.String())
}
func terminalUI(ctx context.Context, call func(ControlRequest) (ControlReply, error)) error {
	u := newTerminalUI(call)
	initial, err := call(ControlRequest{Op: "snapshot"})
	if err != nil {
		return err
	}
	if initial.State == nil {
		return errors.New("node returned no state")
	}
	u.update(*initial.State)
	// QueueUpdateDraw blocks until consumed; launching the producer after the first
	// draw guarantees an event loop is present, including during terminal startup.
	done := make(chan struct{})
	defer close(done)
	var once sync.Once
	u.app.SetAfterDrawFunc(func(tcell.Screen) {
		once.Do(func() {
			go func() {
				tick := time.NewTicker(time.Second)
				defer tick.Stop()
				for {
					select {
					case <-ctx.Done():
						u.app.Stop()
						return
					case <-done:
						return
					case <-tick.C:
						res, err := call(ControlRequest{Op: "snapshot"})
						if err != nil {
							u.app.QueueUpdateDraw(func() { u.notice.SetText("[red]" + terminalText(err.Error()) + "[-]") })
						} else if res.State != nil {
							u.app.QueueUpdateDraw(func() { u.update(*res.State) })
						}
					}
				}
			}()
		})
	})
	return u.app.Run()
}

func run() error {
	dir := flag.String("data", defaultData(), "identity, history and saved settings directory")
	headless := flag.Bool("headless", false, "run as a service without terminal interface")
	attach := flag.Bool("attach", false, "open terminal interface of an already running node")
	status := flag.Bool("status", false, "print running node status and history as JSON")
	send := flag.String("send", "", "queue a message to this Peer ID on a running node")
	message := flag.String("message", "", "text for --send")
	checkPeers := flag.String("check-peers", "", "validate a public peer list file and exit")
	_ = flag.String("ui", "", "deprecated: browser UI removed; use --attach")
	var cfg Config
	flag.IntVar(&cfg.Port, "port", 8081, "WS/WSS port (use 80/443 on public nodes)")
	flag.IntVar(&cfg.DirectPort, "direct-port", 4002, "TCP and UDP/QUIC port; 0 disables extra transports")
	flag.StringVar(&cfg.Bootstrap, "bootstrap", "", "comma-separated public peer multiaddresses")
	flag.StringVar(&cfg.Announce, "announce", "", "comma-separated external multiaddresses")
	flag.StringVar(&cfg.Reachability, "reachability", "auto", "auto, public, private")
	flag.StringVar(&cfg.TLSCert, "tls-cert", "", "PEM TLS certificate chain")
	flag.StringVar(&cfg.TLSKey, "tls-key", "", "PEM TLS private key")
	flag.StringVar(&cfg.IPFamily, "ip-family", "auto", "listener IP family: auto (IPv4 + IPv6), 4 or 6")
	flag.StringVar(&cfg.PeerList, "peer-list", "auto", "public peer list: auto, off, HTTPS URL or local file; auto is disabled with manual --bootstrap")
	flag.Parse()
	if *checkPeers != "" {
		raw, err := os.ReadFile(*checkPeers)
		if err != nil {
			return err
		}
		peers, err := parsePeerList(raw, true)
		if err != nil {
			return err
		}
		fmt.Printf("Valid public peer list: %d peers\n", len(peers))
		return nil
	}
	if flag.NArg() > 0 {
		return errors.New("unexpected positional arguments; use one line without backslashes, or put each backslash at the end of a line")
	}
	if *attach || *status || *send != "" {
		if (*attach && (*status || *send != "")) || (*status && *send != "") {
			return errors.New("choose one of --attach, --status or --send")
		}
		if *attach {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			return terminalUI(ctx, func(q ControlRequest) (ControlReply, error) { return controlCall(*dir, q) })
		}
		q := ControlRequest{Op: "snapshot"}
		if *send != "" {
			q = ControlRequest{Op: "send", To: *send, Text: *message}
		}
		res, err := controlCall(*dir, q)
		if err != nil {
			return err
		}
		if *status {
			return json.NewEncoder(os.Stdout).Encode(res.State)
		}
		fmt.Println(res.ID)
		return nil
	}
	visited := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	var err error
	cfg, err = savedConfig(*dir, cfg, visited)
	if err != nil {
		return err
	}
	port, directPort, cert, keyfile, bootstrap, announce, mode := &cfg.Port, &cfg.DirectPort, &cfg.TLSCert, &cfg.TLSKey, &cfg.Bootstrap, &cfg.Announce, &cfg.Reachability
	interactive := !*headless && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if (*cert == "") != (*keyfile == "") {
		return errors.New("both --tls-cert and --tls-key are required")
	}
	if *port < 1 || *port > 65535 || *directPort < 0 || *directPort > 65535 {
		return errors.New("invalid port")
	}
	if *directPort == *port {
		return errors.New("--direct-port must differ from --port")
	}
	if err = os.MkdirAll(*dir, 0700); err != nil {
		return err
	}
	if err = os.Chmod(*dir, 0700); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(*dir, "node.lock"))
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("data directory already in use")
	}
	defer lock.Unlock()
	identity, err := loadKey(*dir)
	if err != nil {
		return err
	}
	n := &Node{key: identity, dir: *dir, routes: map[peer.ID]Route{}, wake: make(chan struct{}, 1), sendWake: make(chan struct{}, 1), sem: make(chan struct{}, 64), reach: network.ReachabilityUnknown}
	raw, err := os.ReadFile(filepath.Join(*dir, "state.json"))
	if err == nil {
		if err = json.Unmarshal(raw, &n.state); err != nil {
			return fmt.Errorf("state.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if len(n.state.Messages) > maxHistory {
		return errors.New("state history exceeds limit")
	}
	if raw, e := os.ReadFile(filepath.Join(*dir, "sequence.json")); e == nil {
		var seq uint64
		if e = json.Unmarshal(raw, &seq); e != nil {
			return fmt.Errorf("sequence.json: %w", e)
		}
		n.state.Sequence = max(n.state.Sequence, seq)
	} else if !os.IsNotExist(e) {
		return e
	}
	for _, s := range strings.Split(*bootstrap, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		a, e := ma.NewMultiaddr(strings.TrimSpace(s))
		if e != nil {
			return e
		}
		ai, e := peer.AddrInfoFromP2pAddr(a)
		if e != nil {
			return e
		}
		n.boots = append(n.boots, *ai)
	}
	if len(n.boots) > 16 {
		return errors.New("at most 16 bootstrap nodes")
	}
	var advertised []ma.Multiaddr
	for _, s := range strings.Split(*announce, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		a, e := ma.NewMultiaddr(strings.TrimSpace(s))
		if e != nil {
			return e
		}
		advertised = append(advertised, a)
	}
	publicHTTP := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET required", 405)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "P2P messenger node. Use the terminal interface.\n")
	})
	wsopts := []websocket.Option{websocket.WithHTTPHandler(publicHTTP)}
	suffix := "ws"
	if *cert != "" {
		pair, e := tls.LoadX509KeyPair(*cert, *keyfile)
		if e != nil {
			return e
		}
		wsopts = append(wsopts, websocket.WithTLSConfig(&tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}))
		suffix = "tls/ws"
	}
	wsargs := make([]any, len(wsopts))
	for i, opt := range wsopts {
		wsargs[i] = opt
	}
	opts := []libp2p.Option{libp2p.Identity(identity), libp2p.NoTransports, libp2p.Transport(websocket.New, wsargs...), libp2p.Security(noise.ID, noise.New), libp2p.EnableRelay(), libp2p.EnableRelayService(), libp2p.EnableNATService(), libp2p.EnableHolePunching(), libp2p.NATPortMap(), libp2p.UserAgent("p2pmessenger/0.2")}
	listens, e := listenAddresses(cfg, suffix)
	if e != nil {
		return e
	}
	if *directPort > 0 {
		opts = append(opts, libp2p.Transport(tcp.NewTCPTransport), libp2p.Transport(quic.NewTransport))
	}
	opts = append(opts, libp2p.ListenAddrStrings(listens...))
	if len(advertised) > 0 {
		opts = append(opts, libp2p.AddrsFactory(func(addrs []ma.Multiaddr) []ma.Multiaddr { return append(addrs, advertised...) }))
	}
	switch *mode {
	case "public":
		opts = append(opts, libp2p.ForceReachabilityPublic())
		n.reach = network.ReachabilityPublic
	case "private":
		opts = append(opts, libp2p.ForceReachabilityPrivate())
		n.reach = network.ReachabilityPrivate
	case "auto":
	default:
		return errors.New("invalid --reachability")
	}
	source := peerListSource(cfg)
	if source != "" || len(n.boots) > 0 {
		if source == "" {
			opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(n.boots, autorelay.WithNumRelays(min(3, len(n.boots))), autorelay.WithBootDelay(3*time.Second), autorelay.WithBackoff(15*time.Second)))
		} else {
			opts = append(opts, libp2p.EnableAutoRelayWithPeerSource(func(ctx context.Context, num int) <-chan peer.AddrInfo {
				peers := n.bootstrapPeers()
				out := make(chan peer.AddrInfo, min(num, len(peers)))
				defer close(out)
				for _, p := range peers[:min(num, len(peers))] {
					select {
					case out <- p:
					case <-ctx.Done():
						return out
					}
				}
				return out
			}, autorelay.WithNumRelays(3), autorelay.WithMinCandidates(1), autorelay.WithMaxCandidates(16), autorelay.WithMinInterval(5*time.Second), autorelay.WithBootDelay(3*time.Second), autorelay.WithBackoff(15*time.Second)))
		}
	}
	n.h, err = libp2p.New(opts...)
	if err != nil {
		return err
	}
	defer n.h.Close()
	for _, b := range n.boots {
		n.h.Peerstore().AddAddrs(b.ID, b.Addrs, peerstore.PermanentAddrTTL)
	}
	n.h.SetStreamHandler(directoryProtocol, n.bounded(n.handleDirectory))
	n.h.SetStreamHandler(messageProtocol, n.bounded(n.handleMessage))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err = atomicWrite(filepath.Join(*dir, "config.json"), bytesOf(cfg)); err != nil {
		return err
	}
	control, err := n.controlServer()
	if err != nil {
		return err
	}
	defer control.Close()
	// Keep logs off the terminal canvas. Headless services continue logging to stderr.
	if interactive {
		f, e := os.OpenFile(filepath.Join(*dir, "node.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		previous := log.Writer()
		log.SetOutput(f)
		defer func() { log.SetOutput(previous); f.Close() }()
	}
	log.Printf("Peer ID: %s", n.h.ID())
	for _, a := range n.h.Addrs() {
		log.Printf("address: %s/p2p/%s", a, n.h.ID())
	}
	if source != "" {
		log.Printf("public peer list: %s", source)
	}
	if len(n.boots) == 0 && source == "" {
		log.Print("No bootstrap: waiting for incoming peers. AutoNAT needs independent reachable peers to determine reachability.")
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); n.maintain(ctx) }()
	go func() { defer workers.Done(); n.sendLoop(ctx) }()
	if source != "" {
		workers.Add(1)
		go func() { defer workers.Done(); n.discover(ctx, source) }()
	}
	if interactive {
		err = terminalUI(ctx, func(q ControlRequest) (ControlReply, error) { return controlCall(*dir, q) })
	} else {
		<-ctx.Done()
		err = nil
	}
	cancel()
	_ = control.Close()
	workers.Wait()
	return err
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
