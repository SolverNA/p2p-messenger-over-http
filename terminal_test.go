package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

func startClipboardTestUI(t *testing.T) (*TerminalUI, tcell.SimulationScreen, chan ControlRequest, chan string) {
	t.Helper()
	a, b := testNode(t), testNode(t)
	sent := make(chan ControlRequest, 4)
	copied := make(chan string, 8)
	u := newTerminalUI(func(q ControlRequest) (ControlReply, error) { sent <- q; return ControlReply{ID: "queued"}, nil })
	u.writeClipboard = func(s string) error { copied <- s; return nil }
	u.consoleSelection = func(bool) error { return nil }
	u.update(Snapshot{Peer: a.h.ID().String(), Reachability: "Private", Messages: []Entry{{Message: Message{Body: MessageBody{From: b.h.ID().String(), To: a.h.ID().String(), Text: "Исходный [red] текст\nВторая строка 😃", Time: 1}}, Status: "received"}}})
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	screen.SetSize(120, 35)
	u.app.SetScreen(screen)
	ready := make(chan struct{}, 1)
	u.app.SetAfterDrawFunc(func(tcell.Screen) {
		select {
		case ready <- struct{}{}:
		default:
		}
	})
	done := make(chan error, 1)
	go func() { done <- u.app.Run() }()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("no terminal draw")
	}
	t.Cleanup(func() {
		u.app.Stop()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("terminal did not stop")
		}
	})
	return u, screen, sent, copied
}

func waitClipboardUI(t *testing.T, u *TerminalUI, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ok := false
		u.app.QueueUpdateDraw(func() { ok = predicate() })
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("clipboard UI state did not update")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTerminalSystemClipboard(t *testing.T) {
	u, screen, sent, copied := startClipboardTestUI(t)
	peerID := u.state.Messages[0].Message.Body.From
	clipboard := peerID + "\r\n"
	u.app.QueueUpdateDraw(func() { u.readClipboard = func() (string, error) { return clipboard, nil } })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyF4, 0, tcell.ModNone))
	waitClipboardUI(t, u, func() bool { return u.recipient.GetText() == peerID })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	waitClipboardUI(t, u, func() bool { return u.compose.HasFocus() })
	u.app.QueueUpdateDraw(func() { clipboard = "Первая\r\nВторая\t😃" })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModCtrl))
	waitClipboardUI(t, u, func() bool { return u.compose.GetText() == "Первая\nВторая\t😃" })
	select {
	case q := <-sent:
		t.Fatalf("paste sent a message: %+v", q)
	default:
	}
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyCtrlA, 0, tcell.ModCtrl))
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModCtrl))
	select {
	case s := <-copied:
		if s != "Первая\nВторая\t😃" {
			t.Fatal(s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Ctrl+C did not copy")
	}
	// A subsequent key proves Ctrl+C did not terminate the UI.
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyF3, 0, tcell.ModNone))
	select {
	case s := <-copied:
		if s != u.state.Peer {
			t.Fatal("wrong own Peer ID")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Ctrl+C stopped the UI")
	}
	u.app.QueueUpdateDraw(func() { clipboard = "Замена\r\nцеликом" })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyInsert, 0, tcell.ModShift))
	waitClipboardUI(t, u, func() bool { return u.compose.GetText() == "Замена\nцеликом" })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyF5, 0, tcell.ModNone))
	waitClipboardUI(t, u, func() bool { page, _ := u.pages.GetFrontPage(); return page == "copy" })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone))
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone))
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone))
	select {
	case s := <-copied:
		if s != "Исходный [red] текст\nВторая строка 😃" {
			t.Fatal("copied decorations instead of original message", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("message picker did not copy")
	}
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModCtrl))
	select {
	case q := <-sent:
		if q.Text != "Замена\nцеликом" {
			t.Fatal(q)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("explicit send failed")
	}
}

func TestTerminalClipboardErrorsAndMouseToggle(t *testing.T) {
	u, screen, _, _ := startClipboardTestUI(t)
	u.app.QueueUpdateDraw(func() {
		u.app.SetFocus(u.compose)
		u.compose.SetText("Сохранить черновик", true)
		u.compose.Select(0, len(u.compose.GetText()))
		u.readClipboard = func() (string, error) { return "", errors.New("clipboard busy") }
	})
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyF4, 0, tcell.ModNone))
	waitClipboardUI(t, u, func() bool {
		return strings.Contains(u.notice.GetText(false), "clipboard busy") && u.compose.GetText() == "Сохранить черновик"
	})
	u.app.QueueUpdateDraw(func() { u.readClipboard = func() (string, error) { return "", nil } })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyF4, 0, tcell.ModNone))
	waitClipboardUI(t, u, func() bool {
		return strings.Contains(u.notice.GetText(false), "нет текста") && u.compose.GetText() == "Сохранить черновик"
	})
	u.app.QueueUpdateDraw(func() { u.readClipboard = func() (string, error) { return strings.Repeat("x", 16001), nil } })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyF4, 0, tcell.ModNone))
	waitClipboardUI(t, u, func() bool {
		return strings.Contains(u.notice.GetText(false), "отменена") && u.compose.GetText() == "Сохранить черновик"
	})
	u.app.QueueUpdateDraw(func() { u.writeClipboard = func(string) error { return errors.New("copy denied") } })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyCtrlX, 0, tcell.ModCtrl))
	waitClipboardUI(t, u, func() bool {
		return strings.Contains(u.notice.GetText(false), "copy denied") && u.compose.GetText() == "Сохранить черновик"
	})
	modes := make(chan bool, 2)
	u.app.QueueUpdateDraw(func() { u.consoleSelection = func(v bool) error { modes <- v; return nil } })
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyF7, 0, tcell.ModNone))
	select {
	case enabled := <-modes:
		if !enabled {
			t.Fatal("selection not enabled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no mouse toggle")
	}
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyF7, 0, tcell.ModNone))
	select {
	case enabled := <-modes:
		if enabled {
			t.Fatal("selection not disabled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no mouse restore")
	}
}

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
