//go:build windows

package main

import "github.com/dashpalmer269-ai/canaveral/internal/platform/windows"

func platformSources() sources {
	return sources{
		volumes:    windows.VolumeInspector{},
		processes:  windows.ProcessSource{},
		sockets:    windows.SocketSource{},
		privileges: windows.Privileges{},
		files:      windows.FileSystem{},
		signatures: windows.SignatureVerifier{},
	}
}
