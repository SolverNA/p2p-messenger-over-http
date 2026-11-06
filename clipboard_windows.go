package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	clipUser32        = windows.NewLazySystemDLL("user32.dll")
	clipKernel32      = windows.NewLazySystemDLL("kernel32.dll")
	clipOpen          = clipUser32.NewProc("OpenClipboard")
	clipClose         = clipUser32.NewProc("CloseClipboard")
	clipEmpty         = clipUser32.NewProc("EmptyClipboard")
	clipGet           = clipUser32.NewProc("GetClipboardData")
	clipSet           = clipUser32.NewProc("SetClipboardData")
	clipWindow        = clipUser32.NewProc("CreateWindowExW")
	clipDestroyWindow = clipUser32.NewProc("DestroyWindow")
	clipAlloc         = clipKernel32.NewProc("GlobalAlloc")
	clipFree          = clipKernel32.NewProc("GlobalFree")
	clipLock          = clipKernel32.NewProc("GlobalLock")
	clipUnlock        = clipKernel32.NewProc("GlobalUnlock")
	clipSize          = clipKernel32.NewProc("GlobalSize")
	clipMoveMemory    = clipKernel32.NewProc("RtlMoveMemory")
)

func init() {
	nativeClipboardRead = windowsClipboardRead
	nativeClipboardWrite = windowsClipboardWrite
	nativeConsoleSelection = func(enabled bool) error {
		handle := windows.Handle(os.Stdin.Fd())
		var mode uint32
		if err := windows.GetConsoleMode(handle, &mode); err != nil {
			return err
		}
		mode |= windows.ENABLE_EXTENDED_FLAGS
		if enabled {
			mode |= windows.ENABLE_QUICK_EDIT_MODE
		} else {
			mode &^= windows.ENABLE_QUICK_EDIT_MODE
		}
		return windows.SetConsoleMode(handle, mode)
	}
}

func clipboardWindowsError(op string, err error) error {
	if err == nil || errors.Is(err, windows.ERROR_SUCCESS) {
		return fmt.Errorf("%s failed", op)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// A message-only window supplies a real clipboard owner even under ConPTY or
// when there is no console HWND. Keep create/open/read/write/close on one thread.
func withWindowsClipboard(action func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	class, _ := windows.UTF16PtrFromString("STATIC")
	hwnd, _, err := clipWindow.Call(0, uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 0, 0, ^uintptr(2), 0, 0, 0) // HWND_MESSAGE = -3
	if hwnd == 0 {
		return clipboardWindowsError("CreateWindowExW", err)
	}
	defer clipDestroyWindow.Call(hwnd)
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		opened, _, err := clipOpen.Call(hwnd)
		if opened != 0 {
			break
		}
		if time.Now().After(deadline) {
			return clipboardWindowsError("OpenClipboard", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer clipClose.Call()
	return action()
}

func windowsClipboardRead() (text string, err error) {
	err = withWindowsClipboard(func() error {
		handle, _, e := clipGet.Call(13) // CF_UNICODETEXT
		if handle == 0 {
			return clipboardWindowsError("GetClipboardData (text)", e)
		}
		size, _, e := clipSize.Call(handle)
		if size < 2 || size > 4<<20 || size%2 != 0 {
			return errors.New("clipboard text is invalid or exceeds 4 MiB")
		}
		address, _, e := clipLock.Call(handle)
		if address == 0 {
			return clipboardWindowsError("GlobalLock", e)
		}
		defer clipUnlock.Call(handle) // Zero is also a valid successful GlobalUnlock result.
		data := make([]uint16, int(size/2))
		clipMoveMemory.Call(uintptr(unsafe.Pointer(&data[0])), address, size)
		runtime.KeepAlive(data)
		for i, c := range data {
			if c == 0 {
				text = string(utf16.Decode(data[:i]))
				return nil
			}
		}
		return errors.New("clipboard text has no terminator")
	})
	return
}

func windowsClipboardWrite(text string) error {
	if len(text) > 1<<20 {
		return errors.New("clipboard text exceeds 1 MiB")
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	data, err := windows.UTF16FromString(strings.ReplaceAll(text, "\n", "\r\n"))
	if err != nil {
		return err
	}
	return withWindowsClipboard(func() error {
		size := uintptr(len(data) * 2)
		handle, _, e := clipAlloc.Call(0x42, size) // GMEM_MOVEABLE | GMEM_ZEROINIT
		if handle == 0 {
			return clipboardWindowsError("GlobalAlloc", e)
		}
		owned := true
		defer func() {
			if owned {
				clipFree.Call(handle)
			}
		}()
		address, _, e := clipLock.Call(handle)
		if address == 0 {
			return clipboardWindowsError("GlobalLock", e)
		}
		clipMoveMemory.Call(address, uintptr(unsafe.Pointer(&data[0])), size)
		runtime.KeepAlive(data)
		clipUnlock.Call(handle)
		ok, _, e := clipEmpty.Call()
		if ok == 0 {
			return clipboardWindowsError("EmptyClipboard", e)
		}
		ok, _, e = clipSet.Call(13, handle)
		if ok == 0 {
			return clipboardWindowsError("SetClipboardData", e)
		}
		owned = false // Windows now owns the allocation.
		return nil
	})
}
