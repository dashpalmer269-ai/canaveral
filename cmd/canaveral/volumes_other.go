//go:build !windows

package main

import "github.com/dashpalmer269-ai/canaveral/internal/platform"

// volumeInspector returns nil: volume inspection exists only for Windows.
func volumeInspector() platform.VolumeInspector { return nil }
