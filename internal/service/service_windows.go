//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsService reports whether the process was started by the service manager.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type handler struct {
	run func(ctx context.Context) error
	err error
}

func (h *handler) Execute(_ []string, reqs <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case h.err = <-done:
			status <- svc.Status{State: svc.StopPending}
			if h.err != nil {
				return true, 1
			}
			return false, 0
		case r := <-reqs:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 15000}
				cancel()
				h.err = <-done
				return false, 0
			}
		}
	}
}

// Run hands the process to the service manager. run must return when its
// context ends.
func Run(run func(ctx context.Context) error) error {
	h := &handler{run: run}
	if err := svc.Run(Name, h); err != nil {
		return err
	}
	return h.err
}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil, errors.New("access denied: run this from an administrator prompt")
	}
	return m, err
}

func open(m *mgr.Mgr) (*mgr.Service, error) {
	s, err := m.OpenService(Name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil, errors.New("the service is not installed")
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil, errors.New("access denied: run this from an administrator prompt")
	}
	return s, err
}

// Install registers the service to start with the system. An existing
// registration is updated.
func Install(c Config) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	conf := mgr.Config{
		DisplayName:  displayName,
		Description:  description,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}
	s, err := m.OpenService(Name)
	if err == nil {
		// Same service, new program path or profile.
		cur, err := s.Config()
		if err == nil {
			cur.BinaryPathName = windows.ComposeCommandLine(append([]string{c.Exe}, c.args()...))
			cur.StartType, cur.DisplayName, cur.Description = conf.StartType, conf.DisplayName, conf.Description
			err = s.UpdateConfig(cur)
		}
		if err != nil {
			s.Close()
			return err
		}
	} else if s, err = m.CreateService(Name, c.Exe, conf, c.args()...); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return errors.New("access denied: run this from an administrator prompt")
		}
		return err
	}
	defer s.Close()
	// Come back after a crash; give up when it keeps crashing.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.NoAction},
	}, 24*60*60)
	return nil
}

// Uninstall stops and removes the service.
func Uninstall() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := open(m)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = stop(s)
	return s.Delete()
}

// Start starts the installed service.
func Start() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := open(m)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return wait(s, svc.Running)
}

// Stop stops the running service.
func Stop() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := open(m)
	if err != nil {
		return err
	}
	defer s.Close()
	return stop(s)
}

func stop(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	return wait(s, svc.Stopped)
}

func wait(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if want == svc.Running && st.State == svc.Stopped {
			return fmt.Errorf("the service stopped right after starting (exit code %d); see its log file", st.Win32ExitCode)
		}
		if time.Now().After(deadline) {
			return errors.New("the service did not change its state in time")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Status reports the state of the service and the command it runs.
func Status() (state, command string, err error) {
	// Asking needs no administrator rights.
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", "", err
	}
	defer windows.CloseServiceHandle(h)
	name, _ := windows.UTF16PtrFromString(Name)
	sh, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return StateNotInstalled, "", nil
	}
	if err != nil {
		return "", "", err
	}
	s := &mgr.Service{Name: Name, Handle: sh}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", "", err
	}
	if conf, err := s.Config(); err == nil {
		command = conf.BinaryPathName
	}
	switch st.State {
	case svc.Running:
		return StateRunning, command, nil
	case svc.Stopped:
		return StateStopped, command, nil
	case svc.StartPending:
		return "starting", command, nil
	case svc.StopPending:
		return "stopping", command, nil
	}
	return fmt.Sprintf("state %d", st.State), command, nil
}
