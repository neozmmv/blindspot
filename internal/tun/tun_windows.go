package tun

import (
	_ "embed"
)

//go:embed wintun.dll
var WintunDLL []byte
