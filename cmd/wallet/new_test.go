package main

import (
	"testing"
)

func TestNewCmd_Runs(t *testing.T) {
	newBits = 128
	if err := newCmd.RunE(newCmd, nil); err != nil {
		t.Fatalf("newCmd RunE failed: %v", err)
	}
}

func TestNewCmd_InvalidBits(t *testing.T) {
	newBits = 100
	if err := newCmd.RunE(newCmd, nil); err == nil {
		t.Fatal("expected error for invalid bits, got nil")
	}
}
