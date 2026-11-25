//go:build !windows

package intercept

import "os"

// IsElevated reports whether the process may install redirection rules.
func IsElevated() bool { return os.Geteuid() == 0 }
