//go:build windows

package tray

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func findWindow() uintptr {
	cls, _ := windows.UTF16PtrFromString(className)
	h, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(cls)), 0)
	return h
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTrayLifecycle(t *testing.T) {
	var clicked atomic.Int64
	var menus atomic.Int64
	tr := New(Options{
		Menu: func() []Item {
			menus.Add(1)
			return []Item{{ID: 1, Label: "Open", Default: true}, {Separator: true}, {ID: 2, Label: "Exit"}}
		},
		Click: func(id int) { clicked.Store(int64(id)) },
	})
	tr.Set("before the window exists", false)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()

	var hwnd uintptr
	waitFor(t, "the window", func() bool { hwnd = findWindow(); return hwnd != 0 })
	// The window is there before the icons are.
	waitFor(t, "the icons", func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return tr.icons[0] != 0 && tr.icons[1] != 0
	})
	for end := time.Now().Add(2 * time.Second); !tr.Shown() && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if !tr.Shown() {
		// No taskbar in this session (a service, a bare CI runner): everything
		// but the shell's part is still worth testing.
		t.Log("the shell did not take the icon; continuing without it")
	}

	// A menu choice.
	procPostMessage.Call(hwnd, wmTrayCommand, 2, 0)
	waitFor(t, "the click", func() bool { return clicked.Load() == 2 })

	// A left click on the icon acts on the default item.
	procPostMessage.Call(hwnd, wmTrayCallback, 1, wmLButtonUp)
	waitFor(t, "the default action", func() bool { return clicked.Load() == 1 })
	if menus.Load() == 0 {
		t.Error("the menu was never asked for")
	}

	// State changes and a restarted taskbar must not upset it.
	tr.Set("OddlyProxifier - interception on", true)
	tr.Set(strings.Repeat("长", 300)+string(rune(0)), true) // longer than a tooltip can be
	if taskbarCreated != 0 {
		procPostMessage.Call(hwnd, uintptr(taskbarCreated), 0, 0)
	}
	procPostMessage.Call(hwnd, wmTrayCommand, 2, 0)
	clicked.Store(0)
	waitFor(t, "a click after the refresh", func() bool { return clicked.Load() == 2 })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	if tr.Shown() || findWindow() != 0 {
		t.Error("the icon or its window is still there")
	}

	// And once more: the window class can be registered again.
	ctx, cancel = context.WithCancel(context.Background())
	go func() { done <- tr.Run(ctx) }()
	waitFor(t, "the second window", func() bool { return findWindow() != 0 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
