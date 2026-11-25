//go:build !windows

package intercept

import "errors"

// DriverInfo reports that this platform needs no kernel driver.
func DriverInfo() map[string]any {
	return map[string]any{"supported": false, "elevated": IsElevated()}
}

func DriverOp(string) error {
	return errors.New("this platform does not use a kernel driver")
}
