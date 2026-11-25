// Command oddlyproxifier makes applications that have no proxy settings of
// their own connect through SOCKS and HTTPS proxy servers and proxy chains.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"oddlyproxifier/internal/api"
	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/engine"
	"oddlyproxifier/internal/intercept"
	"oddlyproxifier/internal/rules"
	"oddlyproxifier/internal/service"
)

const usage = `OddlyProxifier %s - run applications through SOCKS and HTTPS proxies

Usage:
  oddlyproxifier [run] [flags]     start the engine and its web interface
  oddlyproxifier check [flags]     test the proxies and chains of a profile
  oddlyproxifier match [flags]     show which rule a connection would hit
  oddlyproxifier service <command> run with the system: status, install, start, stop, uninstall
  oddlyproxifier tray [flags]      Windows: notification-area icon for a running engine
  oddlyproxifier driver <command>  Windows driver: status, install, start, stop, uninstall
  oddlyproxifier cleanup           remove redirection rules a crashed engine left behind
  oddlyproxifier version

Run "oddlyproxifier <command> -h" for the flags of a command.
`

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 {
		switch a := args[0]; {
		case a == "-version" || a == "--version":
			cmd, args = "version", nil
		case a == "-h" || a == "-help" || a == "--help":
			cmd, args = "help", nil
		case !strings.HasPrefix(a, "-"):
			cmd, args = a, args[1:]
		}
	}
	var err error
	switch cmd {
	case intercept.GuardArg:
		intercept.RunGuard()
	case "run":
		if service.IsService() {
			// Started by the service manager: it says when to stop.
			err = service.Run(func(ctx context.Context) error { return cmdRun(ctx, args) })
		} else {
			err = cmdRun(context.Background(), args)
		}
	case "service":
		err = cmdService(args)
	case "tray":
		err = cmdTray(args)
	case "check":
		err = cmdCheck(args)
	case "match":
		err = cmdMatch(args)
	case "driver":
		err = cmdDriver(args)
	case "cleanup":
		err = intercept.Cleanup()
	case "version":
		fmt.Printf("OddlyProxifier %s (%s/%s, %s)\n", engine.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	case "help":
		fmt.Printf(usage, engine.Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fmt.Fprintf(os.Stderr, usage, engine.Version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "oddlyproxifier:", err)
		fatalNotice(err)
		os.Exit(1)
	}
}

func newFlags(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: oddlyproxifier %s\n\nFlags:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// ------------------------------------------------------------------- run

var logRank = map[string]int{
	engine.LevelDebug: 0, engine.LevelInfo: 1, engine.LevelWarn: 2, engine.LevelError: 3, "off": 4,
}

func cmdRun(parent context.Context, args []string) error {
	fs := newFlags("run", "[run] [flags]")
	path := fs.String("profile", config.DefaultPath(), "profile `file`; written with defaults when it does not exist")
	apiAddr := fs.String("api", "", "listen `address` of the web interface (default: the profile's, normally 127.0.0.1:9090)")
	open := fs.Bool("open", false, "open the web interface in the default browser")
	noIntercept := fs.Bool("no-intercept", false, "switch interception off in the profile before starting")
	logLevel := fs.String("log", engine.LevelInfo, "console log `level`: debug, info, warn, error or off")
	tray := fs.String("tray", "auto", "Windows notification-area icon: on, off or auto (on when started by double-click)")
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	asService := service.IsService()
	withTray, err := wantTray(*tray, asService)
	if err != nil {
		return err
	}
	minRank, ok := logRank[*logLevel]
	if !ok {
		return fmt.Errorf("unknown log level %q", *logLevel)
	}

	prof, err := config.Load(*path)
	if err != nil {
		return err
	}
	if *noIntercept {
		prof.Options.Intercept = false
	}
	// Store what Load filled in (above all the access token), so that the
	// address of the web interface stays the same from run to run.
	if want, _ := json.MarshalIndent(prof, "", "  "); want != nil {
		if have, _ := os.ReadFile(*path); !bytes.Equal(have, want) {
			if err := config.Save(*path, prof); err != nil {
				fmt.Fprintln(os.Stderr, "warning: the profile cannot be saved:", err)
			}
		}
	}

	eng, err := engine.New(*path, prof)
	if err != nil {
		return err
	}
	eng.SetLogSink(func(e engine.LogEntry) {
		if logRank[e.Level] < minRank {
			return
		}
		fmt.Fprintf(os.Stderr, "%s %-5s %s\n",
			time.UnixMilli(e.Time).Format("15:04:05"), strings.ToUpper(e.Level), e.Msg)
	})

	addr := prof.Options.API
	if *apiAddr != "" {
		addr = *apiAddr
	}
	if withTray {
		// An engine is running already, typically as a service: be its icon
		// rather than fail on the occupied port.
		if c := clientFor(prof, *apiAddr); c.alive() {
			fmt.Println("OddlyProxifier is running already; showing its icon.")
			if *open || doubleClicked() {
				_ = openBrowser(c.url)
			}
			ctx, stop := signal.NotifyContext(parent, os.Interrupt)
			defer stop()
			runTray(ctx, c, false)
			return nil
		}
	}
	// Started by double-click without the rights interception needs: ask for
	// them once. Declining leaves the local proxy listener, which needs none.
	if doubleClicked() && !asService && prof.Options.Intercept && !intercept.IsElevated() && relaunchElevated() {
		return nil
	}
	srv, err := api.Listen(eng, addr, prof.Options.APIToken)
	if err != nil {
		return fmt.Errorf("web interface: %w\n(is OddlyProxifier running already? -api picks another address)", err)
	}

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	eng.Start()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	url := srv.URL()
	fmt.Printf("OddlyProxifier %s\n  Web interface: %s\n  Profile:       %s\n  Stop with Ctrl+C.\n",
		engine.Version, url, *path)
	if ap, err := netip.ParseAddrPort(srv.Addr().String()); err == nil && !ap.Addr().Unmap().IsLoopback() {
		fmt.Fprintln(os.Stderr, "warning: the web interface is reachable from other machines, and its token travels unencrypted")
	}
	if !intercept.IsElevated() && prof.Options.Intercept {
		fmt.Fprintln(os.Stderr, "note: not running as administrator/root, so connections cannot be intercepted;"+
			" the local proxy listener still works")
	}
	if *open || doubleClicked() {
		if err := openBrowser(url); err != nil {
			fmt.Fprintln(os.Stderr, "the browser was not opened:", err)
		}
	}
	trayDone := make(chan struct{})
	if withTray {
		// "Exit" in the icon's menu ends the engine like Ctrl+C does.
		go func() {
			if runTray(ctx, clientFor(prof, srv.Addr().String()), true) {
				close(trayDone)
			}
		}()
	}

	select {
	case <-ctx.Done():
		err = nil
	case <-trayDone:
		err = nil
	case err = <-serveErr:
	}
	stop() // from here on a second Ctrl+C ends the process at once
	srv.Close()
	eng.Stop()
	return err
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		// Through the shell: the browser must not inherit the engine's
		// administrator token.
		return exec.Command("explorer.exe", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	}
	if os.Geteuid() == 0 {
		return errors.New("a browser should not run as root; open the address yourself")
	}
	return exec.Command("xdg-open", url).Start()
}

// ----------------------------------------------------------------- check

func cmdCheck(args []string) error {
	fs := newFlags("check", "check [flags] [proxy or chain name ...]")
	path := fs.String("profile", config.DefaultPath(), "profile `file`")
	target := fs.String("target", "www.gstatic.com:80", "`host:port` to reach through each proxy")
	_ = fs.Parse(args)
	if _, _, err := net.SplitHostPort(*target); err != nil {
		return fmt.Errorf("-target must be host:port")
	}
	prof, err := config.Load(*path)
	if err != nil {
		return err
	}
	eng, err := engine.New("", prof)
	if err != nil {
		return err
	}

	wanted := func(name, id string) bool {
		if fs.NArg() == 0 {
			return true
		}
		for _, a := range fs.Args() {
			if strings.EqualFold(a, name) || a == id {
				return true
			}
		}
		return false
	}
	type job struct {
		kind, id, label string
		res             engine.CheckResult
	}
	var jobs []*job
	for _, p := range prof.Proxies {
		if wanted(p.Name, p.ID) {
			label := fmt.Sprintf("%s (%s %s)", p.Name, p.Type, net.JoinHostPort(p.Host, fmt.Sprint(p.Port)))
			jobs = append(jobs, &job{kind: "proxy", id: p.ID, label: label})
		}
	}
	for _, c := range prof.Chains {
		// Groups are alternatives; their members are tested as proxies.
		if c.Type == config.ChainSimple && wanted(c.Name, c.ID) {
			jobs = append(jobs, &job{kind: "chain", id: c.ID, label: fmt.Sprintf("%s (chain of %d)", c.Name, len(c.Proxies))})
		}
	}
	if len(jobs) == 0 {
		return errors.New("nothing to check: the profile has no matching proxy or chain")
	}

	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j.res = eng.Check(context.Background(), j.kind, j.id, *target)
		}()
	}
	wg.Wait()

	failed := 0
	for _, j := range jobs {
		if j.res.OK {
			fmt.Printf("ok    %-40s %d ms\n", j.label, j.res.Millis)
		} else {
			failed++
			fmt.Printf("FAIL  %-40s %s\n", j.label, j.res.Error)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d cannot reach %s", failed, len(jobs), *target)
	}
	return nil
}

// ----------------------------------------------------------------- match

func cmdMatch(args []string) error {
	fs := newFlags("match", "match [flags]")
	path := fs.String("profile", config.DefaultPath(), "profile `file`")
	app := fs.String("app", "", "application `name` or full path")
	host := fs.String("host", "", "destination host `name` or IP address")
	port := fs.Int("port", 0, "destination `port`")
	_ = fs.Parse(args)
	prof, err := config.Load(*path)
	if err != nil {
		return err
	}
	set, err := rules.Compile(prof)
	if err != nil {
		return err
	}
	name, action := set.Match(rules.Request{App: *app, Host: *host, Port: *port})
	fmt.Printf("rule:   %s\naction: %s\n", name, describeAction(prof, action))
	return nil
}

func describeAction(p *config.Profile, a config.Action) string {
	switch a.Type {
	case config.ActionProxy:
		for _, x := range p.Proxies {
			if x.ID == a.Target {
				return "proxy " + x.Name
			}
		}
	case config.ActionChain:
		for _, c := range p.Chains {
			if c.ID != a.Target {
				continue
			}
			names := make([]string, 0, len(c.Proxies))
			for _, id := range c.Proxies {
				for _, x := range p.Proxies {
					if x.ID == id {
						names = append(names, x.Name)
					}
				}
			}
			sep := " | "
			if c.Type == config.ChainSimple {
				sep = " -> "
			}
			return fmt.Sprintf("%s %s (%s)", c.Type, c.Name, strings.Join(names, sep))
		}
	}
	return a.Type
}

// ---------------------------------------------------------------- driver

func cmdDriver(args []string) error {
	op := "status"
	if len(args) > 0 {
		op = args[0]
	}
	switch op {
	case "install", "start", "stop", "uninstall":
		if err := intercept.DriverOp(op); err != nil {
			return err
		}
	case "status":
	default:
		return fmt.Errorf("unknown driver command %q (status, install, start, stop, uninstall)", op)
	}
	info := intercept.DriverInfo()
	if info["supported"] != true {
		fmt.Println("This platform needs no kernel driver.")
		return nil
	}
	state := "not installed"
	switch {
	case info["error"] != nil:
		state = fmt.Sprint("unknown: ", info["error"])
	case info["running"] == true:
		state = "running"
	case info["installed"] == true:
		state = "installed, not running"
	}
	fmt.Println("driver:      ", state)
	if p, _ := info["path"].(string); p != "" {
		fmt.Println("installed at:", p)
	}
	if f, _ := info["file"].(string); f != "" {
		fmt.Println("driver file: ", f)
	} else {
		fmt.Println("driver file:  OddlyDrv.sys was not found next to the program")
	}
	if info["elevated"] != true {
		fmt.Println("rights:       not an administrator; driver commands need an elevated prompt")
	}
	return nil
}

// --------------------------------------------------------------- service

func cmdService(args []string) error {
	op := "status"
	if len(args) > 0 {
		op, args = args[0], args[1:]
	}
	fs := newFlags("service", "service "+op+" [flags]")
	path := fs.String("profile", config.DefaultPath(), "profile `file` the service runs with (install)")
	apiAddr := fs.String("api", "", "listen `address` of the web interface (install; default: the profile's)")
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	switch op {
	case "install":
		// The service runs as the system, not as you: make sure the profile
		// exists now, where you expect it, and tell where that is.
		prof, err := config.Load(*path)
		if err != nil {
			return err
		}
		if _, err := os.Stat(*path); err != nil {
			if err := config.Save(*path, prof); err != nil {
				return fmt.Errorf("the profile cannot be written: %w", err)
			}
		}
		c, err := service.NewConfig(*path, *apiAddr)
		if err != nil {
			return err
		}
		if err := service.Install(c); err != nil {
			return err
		}
		fmt.Println("installed; it starts with the system and uses the profile")
		fmt.Println(" ", c.Profile)
		fmt.Println(`start it now with "oddlyproxifier service start"`)
		return nil
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			return err
		}
		fmt.Println("uninstalled")
		return nil
	case "start":
		if err := service.Start(); err != nil {
			return err
		}
	case "stop":
		if err := service.Stop(); err != nil {
			return err
		}
	case "status":
	default:
		return fmt.Errorf("unknown service command %q (status, install, start, stop, uninstall)", op)
	}
	state, command, err := service.Status()
	if err != nil {
		return err
	}
	fmt.Println("service:", state)
	if command != "" {
		fmt.Println("command:", command)
	}
	return nil
}
