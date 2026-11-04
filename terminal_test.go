package main

import (
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

func TestTerminalConversationInputAndNetworkScreen(t *testing.T) {
	a, b := testNode(t), testNode(t)
	sent := make(chan ControlRequest, 1)
	u := newTerminalUI(func(q ControlRequest) (ControlReply, error) { sent <- q; return ControlReply{ID: "queued"}, nil })
	s := Snapshot{Peer: a.h.ID().String(), Reachability: "Private", Connections: []Connection{{Peer: b.h.ID().String(), Address: "/ip4/1.2.3.4/tcp/80/ws"}}, Messages: []Entry{{Message: Message{Body: MessageBody{From: b.h.ID().String(), To: a.h.ID().String(), Text: "Привет [red] буквально\x1b[2J", Time: time.Now().UnixMilli()}}, Status: "received"}}}
	u.update(s)
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	screen.SetSize(100, 35)
	u.app.SetScreen(screen)
	ready := make(chan struct{}, 1)
	u.app.SetAfterDrawFunc(func(tcell.Screen) {
		select {
		case ready <- struct{}{}:
		default:
		}
	})
	finished := make(chan error, 1)
	go func() { finished <- u.app.Run() }()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal did not draw")
	}
	t.Cleanup(func() {
		u.app.Stop()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("terminal failed to stop")
		}
	})
	u.app.QueueUpdateDraw(func() { u.recipient.SetText(b.h.ID().String()) })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	deadline := time.Now().Add(2 * time.Second)
	for {
		selected := false
		u.app.QueueUpdateDraw(func() { selected = u.active == b.h.ID().String() && u.compose.HasFocus() })
		if selected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Enter did not open conversation")
		}
		time.Sleep(time.Millisecond)
	}
	u.app.QueueUpdateDraw(func() {
		text := u.history.GetText(false)
		if strings.ContainsRune(text, '\x1b') {
			t.Error("terminal control sequence was not removed")
		}
		if !strings.Contains(text, "[red[]") {
			t.Error("remote style markup was not escaped")
		}
		u.compose.SetText("Ответ из терминала", true)
	})
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	select {
	case q := <-sent:
		if q.Op != "send" || q.To != b.h.ID().String() || q.Text != "Ответ из терминала" {
			t.Fatalf("wrong message: %+v", q)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Enter did not send")
	}
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyF2, 0, tcell.ModNone))
	deadline = time.Now().Add(2 * time.Second)
	for {
		front := ""
		u.app.QueueUpdateDraw(func() { front, _ = u.pages.GetFrontPage() })
		if front == "info" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("F2 did not open network information")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTerminalShowsOfflineAndRetry(t *testing.T) {
	a, b := testNode(t), testNode(t)
	u := newTerminalUI(nil)
	u.active = b.h.ID().String()
	u.update(Snapshot{Peer: a.h.ID().String(), Reachability: "Private", Peers: map[string]PeerDelivery{b.h.ID().String(): {Status: "unavailable", Detail: "peer not found", NextAttempt: time.Now().Add(30 * time.Second).UnixMilli()}}, Messages: []Entry{{Message: Message{Body: MessageBody{From: a.h.ID().String(), To: b.h.ID().String(), Text: "pending"}}, Status: "queued", Error: "peer not found"}}})
	if title := u.history.GetTitle(); !strings.Contains(title, "не в сети / недоступен") || !strings.Contains(title, "повтор через") {
		t.Fatal("missing offline/retry label:", title)
	}
	if !strings.Contains(u.history.GetText(false), "Сообщение сохранено") {
		t.Fatal("queue preservation not shown")
	}
	if !strings.Contains(u.info.GetText(false), "peer not found") {
		t.Fatal("technical failure reason missing from F2")
	}
}
