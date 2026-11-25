//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/tray"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
	procGetUserDefaultUILang  = kernel32.NewProc("GetUserDefaultUILanguage")
)

// ownConsole reports whether the console window belongs to this process
// alone, which is how a program started by double-click finds itself.
func ownConsole() bool {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

var (
	clickOnce sync.Once
	clicked   bool
)

// doubleClicked remembers how the process was started; letting go of the
// console later does not change the answer.
func doubleClicked() bool {
	clickOnce.Do(func() { clicked = ownConsole() })
	return clicked
}

func wantTray(mode string, asService bool) (bool, error) {
	switch mode {
	case "on":
		if asService {
			return false, errors.New(`a service has no desktop to show an icon on; run "oddlyproxifier tray" in your session instead`)
		}
		return true, nil
	case "off":
		return false, nil
	case "auto":
		return !asService && doubleClicked(), nil
	}
	return false, errors.New(`-tray must be "on", "off" or "auto"`)
}

func chinese() bool {
	lang, _, _ := procGetUserDefaultUILang.Call()
	return lang&0x3FF == 0x04
}

func say(en, zh string) string {
	if chinese() {
		return zh
	}
	return en
}

const (
	trayOpen = iota + 1
	trayIntercept
	trayExit
)

// runTray shows the icon until ctx ends or the user picks the last menu
// item, in which case it returns true. owner says that the engine lives in
// this process, so that leaving ends it.
func runTray(ctx context.Context, c trayClient, owner bool) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	intercepting, reachable, exit := false, false, false

	var t *tray.Tray
	refresh := func() {
		rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
		st, err := c.status(rctx)
		rcancel()
		mu.Lock()
		reachable = err == nil
		intercepting = err == nil && st.Intercept.Enabled
		mu.Unlock()
		switch {
		case err != nil:
			t.Set("OddlyProxifier\n"+say("The engine is not running", "引擎未运行"), false)
		case st.Intercept.Enabled && st.Intercept.Active:
			t.Set(fmt.Sprintf("OddlyProxifier\n"+say("Intercepting - %d connections", "正在接管 · %d 个连接"), st.Stats.Active), true)
		case st.Intercept.Enabled:
			t.Set("OddlyProxifier\n"+say("Interception is on but not working; see the interface", "接管已开启但未生效，请打开界面查看"), false)
		default:
			t.Set(fmt.Sprintf("OddlyProxifier\n"+say("Interception off - %d connections", "未接管 · %d 个连接"), st.Stats.Active), false)
		}
	}
	t = tray.New(tray.Options{
		Menu: func() []tray.Item {
			mu.Lock()
			defer mu.Unlock()
			last := tray.Item{ID: trayExit, Label: say("Close this icon", "关闭托盘图标")}
			if owner {
				last.Label = say("Exit OddlyProxifier", "退出 OddlyProxifier")
			}
			return []tray.Item{
				{ID: trayOpen, Label: say("Open OddlyProxifier", "打开 OddlyProxifier"), Default: true},
				{ID: trayIntercept, Label: say("Intercept connections", "接管连接"), Checked: intercepting, Disabled: !reachable},
				{Separator: true},
				last,
			}
		},
		Click: func(id int) {
			switch id {
			case trayOpen:
				_ = openBrowser(c.url)
			case trayIntercept:
				mu.Lock()
				on := !intercepting
				mu.Unlock()
				cctx, ccancel := context.WithTimeout(ctx, 20*time.Second)
				_ = c.setIntercept(cctx, on)
				ccancel()
				refresh()
			case trayExit:
				mu.Lock()
				exit = true
				mu.Unlock()
				cancel()
			}
		},
	})

	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			refresh()
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()

	if doubleClicked() {
		// The console window was opened for us and shows nothing the web
		// interface does not; from here on the icon is the program's face.
		procFreeConsole.Call()
	}
	if err := t.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "the notification-area icon is not available:", err)
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	return exit
}

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func cmdTray(args []string) error {
	fs := flag.NewFlagSet("tray", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: oddlyproxifier tray [flags]\n\n"+
			"Shows the notification-area icon of an engine that is already running,\n"+
			"for example as a service.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	path := fs.String("profile", config.DefaultPath(), "profile `file` of the running engine")
	apiAddr := fs.String("api", "", "`address` of the engine's web interface (default: the profile's)")
	autostart := fs.String("autostart", "", "`on` or `off`: show the icon whenever you sign in")
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	switch *autostart {
	case "":
	case "on":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		words := []string{exe, "tray", "-profile", *path}
		if *apiAddr != "" {
			words = append(words, "-api", *apiAddr)
		}
		k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		if err := k.SetStringValue("OddlyProxifier", windows.ComposeCommandLine(words)); err != nil {
			return err
		}
		fmt.Println("the icon will be shown whenever you sign in")
		return nil
	case "off":
		k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
		if err == nil {
			err = k.DeleteValue("OddlyProxifier")
			k.Close()
		}
		if err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		fmt.Println("the icon is no longer shown when you sign in")
		return nil
	default:
		return errors.New(`-autostart must be "on" or "off"`)
	}

	prof, err := config.Load(*path)
	if err != nil {
		return err
	}
	c := clientFor(prof, *apiAddr)
	if !c.alive() {
		// Not fatal: at sign-in the service may still be starting.
		fmt.Fprintln(os.Stderr, "note: no engine answers at", c.base, "yet; the icon shows when one does")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	runTray(ctx, c, false)
	return nil
}

// relaunchElevated starts this program again as administrator, with the same
// arguments. It reports whether that worked; the caller then exits.
func relaunchElevated() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	var args *uint16
	if len(os.Args) > 1 {
		args, _ = windows.UTF16PtrFromString(windows.ComposeCommandLine(os.Args[1:]))
	}
	var dir *uint16
	if wd, err := os.Getwd(); err == nil {
		dir, _ = windows.UTF16PtrFromString(wd)
	}
	return windows.ShellExecute(0, verb, file, args, dir, windows.SW_SHOWNORMAL) == nil
}

// fatalNotice shows an error to somebody who started the program by
// double-click and would otherwise only see a window close.
func fatalNotice(err error) {
	if !doubleClicked() {
		return
	}
	text, _ := windows.UTF16PtrFromString(err.Error())
	caption, _ := windows.UTF16PtrFromString("OddlyProxifier")
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONERROR)
}
