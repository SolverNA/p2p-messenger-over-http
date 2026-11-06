package main

import (
	"os"
	"strings"
	"testing"
)

// Opt in only on disposable CI desktops: the system clipboard is shared with
// other applications, and a generic `go test` must never replace user data.
func TestWindowsClipboardRoundTrip(t *testing.T) {
	if os.Getenv("P2P_TEST_WINDOWS_CLIPBOARD") != "1" {
		t.Skip("native clipboard test is opt-in")
	}
	previous, err := windowsClipboardRead()
	if err == nil {
		defer windowsClipboardWrite(previous)
	}
	want := "P2P clipboard: Привет 😃\n第二行"
	if err := windowsClipboardWrite(want); err != nil {
		t.Fatal(err)
	}
	got, err := windowsClipboardRead()
	if err != nil {
		t.Fatal(err)
	}
	if clipboardText(got) != want {
		t.Fatalf("UTF-16 round trip mismatch: %q", got)
	}
	if err := windowsClipboardWrite("invalid\x00text"); err == nil {
		t.Fatal("embedded NUL accepted")
	}
	if err := windowsClipboardWrite(strings.Repeat("x", (1<<20)+1)); err == nil {
		t.Fatal("oversized clipboard write accepted")
	}
	got, err = windowsClipboardRead()
	if err != nil || clipboardText(got) != want {
		t.Fatal("rejected write destroyed clipboard", err)
	}
}
