//go:build !windows

package platform

func WasLaunchedFromTerminal() bool { return false }
func AttachToParentConsole()        {}
