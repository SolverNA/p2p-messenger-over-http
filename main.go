// P2P messenger: a single source file with an embedded browser interface.
package main

import (
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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

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
)

const (
	directoryProtocol protocol.ID = "/p2pmessenger/directory/1.0.0"
	messageProtocol   protocol.ID = "/p2pmessenger/message/1.0.0"
	maxFrame                      = 128 << 10
	maxHistory                    = 10000
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
	h        host.Host
	key      crypto.PrivKey
	dir      string
	boots    []peer.AddrInfo
	mu       sync.Mutex
	state    DiskState
	routes   map[peer.ID]Route
	reach    network.Reachability
	wake     chan struct{}
	sendWake chan struct{}
	sem      chan struct{}
	token    string
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
	if err := n.saveLocked(); err != nil {
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
	for _, b := range n.boots {
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
	// A failed attempt must fetch a new registration instead of retrying a stale
	// address until its TTL expires after a network change.
	defer func() {
		if result != nil {
			n.mu.Lock()
			delete(n.routes, id)
			n.mu.Unlock()
		}
	}()
	// Refresh routing even when a stale direct address remains in the peerstore.
	if len(n.h.Network().ConnsToPeer(id)) == 0 {
		r, e := n.lookup(ctx, id, 1, "")
		if e != nil {
			return e
		}
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
	s, err := n.h.NewStream(network.WithAllowLimitedConn(ctx, "encrypted chat through relay"), id, messageProtocol)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
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
		return errors.New(ack.Error)
	}
	return nil
}
func (n *Node) sendLoop(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
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
			if e.Status == "queued" {
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
							if saveErr := n.saveLocked(); saveErr != nil {
								*e = old
								log.Print(saveErr)
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
		for _, b := range n.boots {
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

func jsonReply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
func (n *Node) status() any {
	n.mu.Lock()
	reach := n.reach.String()
	queued := 0
	for _, e := range n.state.Messages {
		if e.Status == "queued" {
			queued++
		}
	}
	n.mu.Unlock()
	addresses := []string{}
	for _, a := range n.h.Addrs() {
		addresses = append(addresses, a.String()+"/p2p/"+n.h.ID().String())
	}
	connections := []map[string]any{}
	for _, c := range n.h.Network().Conns() {
		connections = append(connections, map[string]any{"peer": c.RemotePeer().String(), "address": c.RemoteMultiaddr().String(), "relay": c.Stat().Limited})
	}
	pub, _ := crypto.MarshalPublicKey(n.key.GetPublic())
	return map[string]any{"peer": n.h.ID().String(), "public_key": base64.StdEncoding.EncodeToString(pub), "reachability": reach, "addresses": addresses, "connections": connections, "queued": queued}
}
func (n *Node) uiHandler(listenHost string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, strings.ReplaceAll(page, "__TOKEN__", n.token))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) { jsonReply(w, n.status()) })
	mux.HandleFunc("/api/messages", func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		jsonReply(w, n.state.Messages)
	})
	mux.HandleFunc("/api/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		var q struct {
			To   string `json:"to"`
			Text string `json:"text"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 20000)).Decode(&q); err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		id, err := n.queue(q.To, q.Text)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		jsonReply(w, map[string]string{"id": id})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+n.token+"'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		hostname, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			hostname = r.Host
		}
		if hostname != "localhost" && hostname != listenHost && hostname != "127.0.0.1" && hostname != "::1" {
			http.Error(w, "invalid Host", 403)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			if e != nil || u.Host != r.Host || u.Scheme != "http" {
				http.Error(w, "invalid Origin", 403)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-Node-Token") != n.token {
			http.Error(w, "invalid token", 403)
			return
		}
		if r.Method != "GET" && r.URL.Path != "/api/send" {
			http.Error(w, "method not allowed", 405)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func run() error {
	dir := flag.String("data", "./node-data", "identity and message storage directory")
	ui := flag.String("ui", "127.0.0.1:8080", "local browser interface (loopback only)")
	port := flag.Int("port", 0, "WS/WSS port; default 80 without TLS, 443 with TLS")
	cert := flag.String("tls-cert", "", "PEM TLS certificate, including intermediate chain")
	keyfile := flag.String("tls-key", "", "PEM TLS private key")
	bootstrap := flag.String("bootstrap", "", "comma-separated public peer multiaddresses including /p2p/ID")
	announce := flag.String("announce", "", "comma-separated external multiaddresses without /p2p/ID")
	mode := flag.String("reachability", "auto", "auto, public, private (override for testing or known network setup)")
	directPort := flag.Int("direct-port", 4002, "TCP and UDP/QUIC port for direct NAT traversal; 0 disables extra transports")
	flag.Parse()
	if (*cert == "") != (*keyfile == "") {
		return errors.New("both --tls-cert and --tls-key are required")
	}
	if *port == 0 {
		if *cert != "" {
			*port = 443
		} else {
			*port = 80
		}
	}
	if *port < 1 || *port > 65535 || *directPort < 0 || *directPort > 65535 {
		return errors.New("invalid port")
	}
	if *directPort == *port {
		return errors.New("--direct-port must differ from --port")
	}
	uiHost, _, err := net.SplitHostPort(*ui)
	if err != nil {
		return err
	}
	ip := net.ParseIP(uiHost)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("--ui must bind a loopback IP (127.0.0.1 or ::1)")
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
	n := &Node{key: identity, dir: *dir, routes: map[peer.ID]Route{}, wake: make(chan struct{}, 1), sendWake: make(chan struct{}, 1), sem: make(chan struct{}, 64), token: randomID(), reach: network.ReachabilityUnknown}
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
		_, _ = io.WriteString(w, "P2P messenger node. Open the local interface on 127.0.0.1:8080.\n")
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
	opts := []libp2p.Option{libp2p.Identity(identity), libp2p.NoTransports, libp2p.Transport(websocket.New, wsargs...), libp2p.Security(noise.ID, noise.New), libp2p.EnableRelay(), libp2p.EnableRelayService(), libp2p.EnableNATService(), libp2p.EnableHolePunching(), libp2p.NATPortMap(), libp2p.UserAgent("p2pmessenger/0.1")}
	listens := []string{fmt.Sprintf("/ip4/0.0.0.0/tcp/%d/%s", *port, suffix)}
	if *directPort > 0 {
		opts = append(opts, libp2p.Transport(tcp.NewTCPTransport), libp2p.Transport(quic.NewTransport))
		listens = append(listens, fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *directPort), fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", *directPort))
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
	if len(n.boots) > 0 {
		opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(n.boots, autorelay.WithNumRelays(min(3, len(n.boots))), autorelay.WithBootDelay(3*time.Second), autorelay.WithBackoff(15*time.Second)))
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
	ln, err := net.Listen("tcp", *ui)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: n.uiHandler(uiHost), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ln) }()
	log.Printf("Peer ID: %s", n.h.ID())
	log.Printf("interface: http://%s", ln.Addr())
	for _, a := range n.h.Addrs() {
		log.Printf("address: %s/p2p/%s", a, n.h.ID())
	}
	if len(n.boots) == 0 {
		log.Print("No bootstrap: waiting for incoming peers. AutoNAT needs independent reachable peers to determine reachability.")
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); n.maintain(ctx) }()
	go func() { defer workers.Done(); n.sendLoop(ctx) }()
	select {
	case <-ctx.Done():
	case err = <-serveErr:
		cancel()
	}
	cancel()
	_ = server.Close()
	workers.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

const page = `<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Связь · P2P</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#10141b;color:#e5eaf2}*{box-sizing:border-box}body{margin:0}main{max-width:1100px;margin:auto;padding:28px}header{display:flex;align-items:center;justify-content:space-between;gap:18px}h1{font-size:27px;margin:0}small,.muted{color:#9baabd}#role{background:#233546;padding:8px 12px;border-radius:20px;font-size:13px}.layout{display:grid;grid-template-columns:310px 1fr;gap:20px;margin-top:24px}.card{background:#181f2a;border:1px solid #2b3646;border-radius:16px;padding:20px;min-width:0}label{display:block;font-size:13px;color:#aebed0;margin-bottom:8px}input,textarea,button{font:inherit;border-radius:9px;border:1px solid #38465b;padding:11px;background:#101722;color:#e5eaf2;width:100%}textarea{resize:vertical;min-height:82px}button{background:#b5f380;color:#142008;border:0;cursor:pointer;font-weight:600}button:disabled{opacity:.5;cursor:wait}.row{display:flex;gap:10px;margin-top:10px}.row button{width:auto}code{display:block;overflow-wrap:anywhere;font-size:12px;line-height:1.65;color:#b5f380}.section{margin-top:22px}#messages{height:410px;overflow:auto;display:flex;flex-direction:column;gap:12px;padding:12px 0}.bubble{max-width:90%;align-self:flex-start;background:#263346;padding:12px 15px;border-radius:12px;white-space:pre-wrap;overflow-wrap:anywhere}.bubble.mine{align-self:flex-end;background:#284330}.bubble small{display:block;font-size:11px;margin-top:6px}.error{color:#f4b0a2;font-size:13px;overflow-wrap:anywhere}#contacts button{background:#243143;color:#dbe5f3;font-size:12px;overflow-wrap:anywhere;text-align:left;margin-top:7px}details{margin-top:16px;font-size:13px}summary{cursor:pointer;color:#aebed0}#connections{font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}#notice{min-height:22px}a{color:#b5f380}@media(max-width:760px){main{padding:15px}.layout{grid-template-columns:1fr}#messages{height:350px}}
</style>
<main><header><div><h1>Связь <span class="muted">/ P2P</span></h1><small>Личные сообщения · ключ вместо аккаунта</small></div><span id="role">Подключение…</span></header>
<div class="layout"><aside class="card"><label>Ваш Peer ID · адрес для собеседника</label><code id="identity"></code><div class="row"><button id="copy">Копировать</button></div><div class="section"><label>Собеседник</label><input id="recipient" placeholder="12D3KooW…" autocomplete="off" spellcheck="false"></div><div id="contacts" class="section"></div><details><summary>Адреса узла</summary><code id="addresses"></code></details><details><summary>Соединения</summary><div id="connections"></div></details><div class="section"><small>Ключи и история хранятся у этого узла. Для доставки оба узла должны работать; при обрыве сообщение остаётся в очереди.</small></div></aside>
<section class="card"><label id="chatTitle">Личная беседа</label><div id="messages"><p class="muted">Вставьте Peer ID собеседника, чтобы начать общение.</p></div><form id="form"><textarea id="text" placeholder="Написать сообщение…" maxlength="16000" required></textarea><div class="row"><button id="send" type="submit">Отправить</button></div><p id="notice" class="error" role="status"></p></form><small>Канал защищён между пирами, в том числе при передаче через реле.</small></section></div></main>
<script nonce="__TOKEN__">
const token='__TOKEN__', el=id=>document.getElementById(id);let self='',entries=[],lastRender='';
async function api(path,body){const r=await fetch(path,{method:body?'POST':'GET',headers:{'X-Node-Token':token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});if(!r.ok)throw Error(await r.text());return r.json()}
function render(){const peer=el('recipient').value.trim(), filtered=entries.filter(e=>e.message.body.from===peer||e.message.body.to===peer),key=JSON.stringify([peer,filtered]);if(key===lastRender)return;lastRender=key;el('messages').replaceChildren();if(!filtered.length){const p=document.createElement('p');p.className='muted';p.textContent=peer?'Сообщений пока нет.':'Вставьте Peer ID собеседника, чтобы начать общение.';el('messages').append(p)}for(const e of filtered){const b=e.message.body,d=document.createElement('div');d.className='bubble'+(b.from===self?' mine':'');d.textContent=b.text;const s=document.createElement('small');s.textContent=new Date(b.time).toLocaleString()+' · '+({queued:'В очереди',delivered:'Доставлено',received:'Получено'}[e.status]||e.status);d.append(s);if(e.error){const er=document.createElement('small');er.className='error';er.textContent=e.error;d.append(er)}el('messages').append(d)}el('messages').scrollTop=el('messages').scrollHeight}
async function refresh(){try{const [s,m]=await Promise.all([api('/api/status'),api('/api/messages')]);self=s.peer;entries=m||[];el('identity').textContent=self;el('role').textContent=({Public:'Публичный узел',Private:'За NAT',Unknown:'Определяем доступность'}[s.reachability]||s.reachability)+' · '+s.connections.length+' соед.';el('addresses').textContent=s.addresses.join('\n');el('connections').textContent=s.connections.map(c=>c.peer+'\n'+(c.relay?'Реле':'Прямое')+' · '+c.address).join('\n\n')||'Нет соединений';const peers=[...new Set(entries.map(e=>e.message.body.from===self?e.message.body.to:e.message.body.from))];el('contacts').replaceChildren();for(const p of peers){const b=document.createElement('button');b.textContent=p;b.onclick=()=>{el('recipient').value=p;render()};el('contacts').append(b)}render()}catch(e){el('notice').textContent='Нет связи с локальным узлом: '+e.message}}
el('recipient').addEventListener('input',render);el('copy').onclick=async()=>{try{await navigator.clipboard.writeText(self);el('notice').textContent='Peer ID скопирован'}catch{el('notice').textContent='Выделите и скопируйте Peer ID вручную'}};
el('form').onsubmit=async e=>{e.preventDefault();el('send').disabled=true;try{await api('/api/send',{to:el('recipient').value.trim(),text:el('text').value});el('text').value='';el('notice').textContent='Сообщение добавлено в очередь';await refresh()}catch(e){el('notice').textContent=e.message}finally{el('send').disabled=false}};
async function poll(){await refresh();setTimeout(poll,2000)}poll();
</script></html>`
