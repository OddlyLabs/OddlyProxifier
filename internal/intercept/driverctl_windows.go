//go:build windows

package intercept

import "errors"

// DriverInfo describes the kernel driver for the UI.
func DriverInfo() map[string]any {
	info := map[string]any{
		"supported": true,
		"elevated":  IsElevated(),
		"file":      FindDriverFile(),
	}
	st, err := QueryDriver()
	if err != nil {
		info["error"] = err.Error()
		return info
	}
	info["installed"], info["running"], info["path"] = st.Installed, st.Running, st.Path
	return info
}

// DriverOp runs a driver management operation by name.
func DriverOp(op string) error {
	if !IsElevated() {
		return errors.New("administrator rights are required")
	}
	switch op {
	case "install":
		if err := InstallDriver(""); err != nil {
			return err
		}
		return StartDriver()
	case "start":
		return StartDriver()
	case "stop":
		return StopDriver()
	case "uninstall":
		return UninstallDriver()
	}
	return errors.New("unknown operation")
}
