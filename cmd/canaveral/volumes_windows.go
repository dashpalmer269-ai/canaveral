//go:build windows

package main

import (
	"github.com/dashpalmer269-ai/canaveral/internal/platform"
	"github.com/dashpalmer269-ai/canaveral/internal/platform/windows"
)

func volumeInspector() platform.VolumeInspector { return windows.VolumeInspector{} }
