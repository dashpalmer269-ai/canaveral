//go:build !windows

package main

// platformSources returns no sources: collection exists only for Windows.
func platformSources() sources { return sources{} }
