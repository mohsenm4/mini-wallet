package main

import (
	"testing"
)

const testMnemonic = "test test test test test test test test test test test junk"

func TestDeriveCmd_MissingMnemonic(t *testing.T) {
	t.Setenv("WALLET_MNEMONIC", "")
	derivePath = ""
	deriveIndex = 0
	if err := deriveCmd.RunE(deriveCmd, nil); err == nil {
		t.Fatal("expected error when WALLET_MNEMONIC unset, got nil")
	}
}

func TestDeriveCmd_DefaultPath(t *testing.T) {
	t.Setenv("WALLET_MNEMONIC", testMnemonic)
	t.Setenv("WALLET_PASSPHRASE", "")
	derivePath = ""
	deriveIndex = 0
	if err := deriveCmd.RunE(deriveCmd, nil); err != nil {
		t.Fatalf("deriveCmd RunE failed: %v", err)
	}
}

func TestDeriveCmd_ExplicitPath(t *testing.T) {
	t.Setenv("WALLET_MNEMONIC", testMnemonic)
	derivePath = "m/44'/60'/0'/0/5"
	deriveIndex = 0
	if err := deriveCmd.RunE(deriveCmd, nil); err != nil {
		t.Fatalf("deriveCmd RunE failed: %v", err)
	}
}

func TestDeriveCmd_BadPath(t *testing.T) {
	t.Setenv("WALLET_MNEMONIC", testMnemonic)
	derivePath = "not-a-path"
	if err := deriveCmd.RunE(deriveCmd, nil); err == nil {
		t.Fatal("expected error for bad path, got nil")
	}
}
