package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var readPasswordFn = readPassword

func TestExportKeystore_ToStdout(t *testing.T) {
	t.Setenv(
		"WALLET_MNEMONIC",
		"test test test test test test test test test test test junk",
	)
	t.Setenv("WALLET_PASSPHRASE", "")
	t.Setenv("WALLET_PASSWORD", "test-password")

	exportOut = ""

	err := runExportKeystore(exportKeystoreCmd, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportKeystore_MissingMnemonic(t *testing.T) {
	t.Setenv("WALLET_MNEMONIC", "")
	t.Setenv("WALLET_PASSPHRASE", "")

	err := runExportKeystore(exportKeystoreCmd, nil)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "WALLET_MNEMONIC environment variable is not set" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportKeystore_ToFile(t *testing.T) {
	t.Setenv(
		"WALLET_MNEMONIC",
		"test test test test test test test test test test test junk",
	)
	t.Setenv("WALLET_PASSPHRASE", "")
	t.Setenv("WALLET_PASSWORD", "test-password")

	tmpFile := t.TempDir() + "/keystore.json"
	exportOut = tmpFile

	err := runExportKeystore(exportKeystoreCmd, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatalf("expected keystore file to be created, but it does not exist")
	}
}
func TestExportKeystore_Roundtrip(t *testing.T) {
	t.Setenv(
		"WALLET_MNEMONIC",
		"test test test test test test test test test test test junk",
	)
	t.Setenv("WALLET_PASSPHRASE", "")
	t.Setenv("WALLET_PASSWORD", "test-password")

	tmpFile := filepath.Join(t.TempDir(), "keystore.json")
	exportOut = tmpFile

	err := runExportKeystore(exportKeystoreCmd, nil)
	if err != nil {
		t.Fatalf("unexpected error during export: %v", err)
	}

	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatalf("expected keystore file to be created: %v", err)
	}

	output := captureStdout(t, func() {
		err := runImportKeystore(importKeystoreCmd, []string{tmpFile})
		if err != nil {
			t.Fatalf("unexpected error during import: %v", err)
		}
	})

	expectedAddress := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	if !strings.Contains(output, expectedAddress) {
		t.Fatalf(
			"expected address %s, got %s",
			expectedAddress,
			output,
		)
	}
}
