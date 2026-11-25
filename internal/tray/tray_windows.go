//go:build windows

// Package tray puts an icon with a menu into the Windows notification area.
// It talks to user32 and shell32 directly, so the program stays free of cgo.
package tray

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Item is one line of the menu.
type Item struct {
	ID        int // above 0; handed to Options.Click
	Label     string
	Checked   bool
	Disabled  bool
	Default   bool // shown in bold; also what a click on the icon does
	Separator bool
}

// Options describes the icon.
type Options struct {
	// Menu builds the menu each time it is opened.
	Menu func() []Item
	// Click is called, on its own goroutine, with the ID of the chosen item.
	Click func(id int)
}

// Tray is a notification-area icon.
type Tray struct {
	opt Options

	mu     sync.Mutex
	hwnd   uintptr
	tip    string
	active bool
	added  bool
	icons  [2]uintptr // inactive, active
}

// New prepares an icon; Run shows it.
func New(o Options) *Tray { return &Tray{opt: o, tip: "OddlyProxifier", active: true} }

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassEx     = user32.NewProc("RegisterClassExW")
	procUnregisterClass     = user32.NewProc("UnregisterClassW")
	procCreateWindowEx      = user32.NewProc("CreateWindowExW")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procDefWindowProc       = user32.NewProc("DefWindowProcW")
	procGetMessage          = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessage     = user32.NewProc("DispatchMessageW")
	procPostMessage         = user32.NewProc("PostMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procRegisterWindowMsg   = user32.NewProc("RegisterWindowMessageW")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenu          = user32.NewProc("AppendMenuW")
	procSetMenuDefaultItem  = user32.NewProc("SetMenuDefaultItem")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	procCreateIconFromRes   = user32.NewProc("CreateIconFromResourceEx")
	procDestroyIcon         = user32.NewProc("DestroyIcon")
	procFindWindow          = user32.NewProc("FindWindowW")
	procShellNotifyIcon     = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandle     = kernel32.NewProc("GetModuleHandleW")
)

const (
	className = "OddlyProxifierTray"

	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmNull          = 0x0000
	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	wmContextMenu   = 0x007B
	wmApp           = 0x8000
	wmTrayCallback  = wmApp + 1 // from the shell: something happened on the icon
	wmTrayRefresh   = wmApp + 2 // from Set: tooltip or state changed
	wmTrayCommand   = wmApp + 3 // wParam: the ID of a menu item to act on

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2
	nifMsg    = 1
	nifIcon   = 2
	nifTip    = 4

	mfString    = 0x0000
	mfGrayed    = 0x0001
	mfChecked   = 0x0008
	mfSeparator = 0x0800

	tpmRightButton = 0x0002
	tpmNoNotify    = 0x0080
	tpmReturnCmd   = 0x0100

	smCxSmIcon = 49
)

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   uintptr
	icon       uintptr
	cursor     uintptr
	background uintptr
	menuName   *uint16
	className  *uint16
	iconSm     uintptr
}

type point struct{ x, y int32 }

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
	private uint32
}

type notifyIconData struct {
	size            uint32
	hwnd            uintptr
	id              uint32
	flags           uint32
	callbackMessage uint32
	icon            uintptr
	tip             [128]uint16
	state           uint32
	stateMask       uint32
	info            [256]uint16
	version         uint32
	infoTitle       [64]uint16
	infoFlags       uint32
	guidItem        windows.GUID
	balloonIcon     uintptr
}

// The window procedure is one callback for the whole process; it finds its
// Tray through this table.
var (
	traysMu sync.Mutex
	trays   = map[uintptr]*Tray{}
	wndProc = syscall.NewCallback(func(hwnd uintptr, m uint32, wp, lp uintptr) uintptr {
		traysMu.Lock()
		t := trays[hwnd]
		traysMu.Unlock()
		if t != nil {
			if r, done := t.handle(hwnd, m, wp, lp); done {
				return r
			}
		}
		r, _, _ := procDefWindowProc.Call(hwnd, uintptr(m), wp, lp)
		return r
	})
	taskbarCreated uint32
)

// Run shows the icon and serves it until ctx ends. It returns an error only
// when the window cannot be created; a missing shell (no taskbar yet) is
// waited out.
func (t *Tray) Run(ctx context.Context) error {
	// A window belongs to the thread that made it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	inst, _, _ := procGetModuleHandle.Call(0)
	cls, _ := windows.UTF16PtrFromString(className)
	wc := wndClassEx{wndProc: wndProc, instance: inst, className: cls}
	wc.size = uint32(unsafe.Sizeof(wc))
	if a, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); a == 0 &&
		!errors.Is(err, windows.ERROR_CLASS_ALREADY_EXISTS) {
		return err
	}
	name, _ := windows.UTF16PtrFromString("TaskbarCreated")
	if m, _, _ := procRegisterWindowMsg.Call(uintptr(unsafe.Pointer(name))); m != 0 {
		taskbarCreated = uint32(m)
	}
	// A hidden top-level window rather than a message-only one: only top-level
	// windows hear that the taskbar was created again.
	title, _ := windows.UTF16PtrFromString("OddlyProxifier")
	hwnd, _, err := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)),
		0, 0, 0, 0, 0, 0, 0, inst, 0)
	if hwnd == 0 {
		return err
	}
	traysMu.Lock()
	trays[hwnd] = t
	traysMu.Unlock()

	size, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	if size < 16 || size > 256 {
		size = 16
	}
	t.mu.Lock()
	t.hwnd = hwnd
	t.icons[0], t.icons[1] = makeIcon(int(size), false), makeIcon(int(size), true)
	t.mu.Unlock()
	t.show()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			procPostMessage.Call(hwnd, wmClose, 0, 0)
		case <-stop:
		}
	}()

	var m msg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}

	traysMu.Lock()
	delete(trays, hwnd)
	traysMu.Unlock()
	t.mu.Lock()
	for i, ic := range t.icons {
		if ic != 0 {
			procDestroyIcon.Call(ic)
			t.icons[i] = 0
		}
	}
	t.hwnd = 0
	t.mu.Unlock()
	procUnregisterClass.Call(uintptr(unsafe.Pointer(cls)), inst)
	return nil
}

// Set changes the tooltip and whether the icon shows the active state. It
// may be called from any goroutine, before or while Run runs.
func (t *Tray) Set(tip string, active bool) {
	t.mu.Lock()
	changed := t.tip != tip || t.active != active
	t.tip, t.active = tip, active
	hwnd := t.hwnd
	t.mu.Unlock()
	if changed && hwnd != 0 {
		procPostMessage.Call(hwnd, wmTrayRefresh, 0, 0)
	}
}

// Shown reports whether the shell has accepted the icon.
func (t *Tray) Shown() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.added
}

// show adds the icon or brings it up to date. UI thread only.
func (t *Tray) show() {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := notifyIconData{hwnd: t.hwnd, id: 1, flags: nifMsg | nifIcon | nifTip, callbackMessage: wmTrayCallback}
	d.size = uint32(unsafe.Sizeof(d))
	d.icon = t.icons[0]
	if t.active {
		d.icon = t.icons[1]
	}
	// At most 127 units and the terminator, which the zeroed array supplies.
	tip := utf16.Encode([]rune(strings.ReplaceAll(t.tip, string(rune(0)), " ")))
	copy(d.tip[:len(d.tip)-1], tip)
	op := uintptr(nimModify)
	if !t.added {
		op = nimAdd
	}
	r, _, _ := procShellNotifyIcon.Call(op, uintptr(unsafe.Pointer(&d)))
	if op == nimAdd {
		t.added = r != 0
	}
}

func (t *Tray) remove() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.added {
		return
	}
	d := notifyIconData{hwnd: t.hwnd, id: 1}
	d.size = uint32(unsafe.Sizeof(d))
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&d)))
	t.added = false
}

func (t *Tray) click(id int) {
	if id > 0 && t.opt.Click != nil {
		go t.opt.Click(id)
	}
}

func (t *Tray) items() []Item {
	if t.opt.Menu == nil {
		return nil
	}
	return t.opt.Menu()
}

func (t *Tray) handle(hwnd uintptr, m uint32, wp, lp uintptr) (uintptr, bool) {
	switch m {
	case wmTrayCallback:
		switch uint32(lp) & 0xFFFF {
		case wmLButtonUp, wmLButtonDblClk:
			for _, it := range t.items() {
				if it.Default && !it.Disabled {
					t.click(it.ID)
					break
				}
			}
		case wmRButtonUp, wmContextMenu:
			t.popup(hwnd)
		}
		return 0, true
	case wmTrayRefresh:
		t.show()
		return 0, true
	case wmTrayCommand:
		t.click(int(wp))
		return 0, true
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0, true
	case wmDestroy:
		t.remove()
		procPostQuitMessage.Call(0)
		return 0, true
	}
	if taskbarCreated != 0 && m == taskbarCreated {
		// Explorer restarted and forgot every icon.
		t.mu.Lock()
		t.added = false
		t.mu.Unlock()
		t.show()
		return 0, true
	}
	return 0, false
}

func (t *Tray) popup(hwnd uintptr) {
	items := t.items()
	if len(items) == 0 {
		return
	}
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	for _, it := range items {
		if it.Separator {
			procAppendMenu.Call(menu, mfSeparator, 0, 0)
			continue
		}
		flags := uintptr(mfString)
		if it.Checked {
			flags |= mfChecked
		}
		if it.Disabled {
			flags |= mfGrayed
		}
		label, _ := windows.UTF16PtrFromString(it.Label)
		procAppendMenu.Call(menu, flags, uintptr(it.ID), uintptr(unsafe.Pointer(label)))
		if it.Default {
			procSetMenuDefaultItem.Call(menu, uintptr(it.ID), 0)
		}
	}
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// Without this the menu stays open when the user clicks elsewhere.
	procSetForegroundWindow.Call(hwnd)
	id, _, _ := procTrackPopupMenu.Call(menu, tpmRightButton|tpmNoNotify|tpmReturnCmd,
		uintptr(pt.x), uintptr(pt.y), 0, hwnd, 0)
	procPostMessage.Call(hwnd, wmNull, 0, 0)
	t.click(int(id))
}

// makeIcon renders the program's mark and turns it into an icon handle.
func makeIcon(size int, active bool) uintptr {
	res := iconResource(size, active)
	h, _, _ := procCreateIconFromRes.Call(uintptr(unsafe.Pointer(&res[0])), uintptr(len(res)),
		1, 0x00030000, uintptr(size), uintptr(size), 0)
	return h
}
