package main

import (
	"testing"

	"github.com/neozmmv/blindspot/internal/utils"
)

func TestGetBlindspotDir(t *testing.T) {
	dir := utils.GetBlindspotDir()
	if dir == "" {
		t.Fatal("GetBlindspotDir returned an empty string!")
	}
	t.Logf("BLINDSPOT DIRECTORY: %v\n", dir)
}
