package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunImportKeystore_FileNotFound(t *testing.T) {
	t.Setenv("WALLET_PASSWORD", "any-password")

	err := runImportKeystore(importKeystoreCmd, []string{
		"/path/to/non-existent-keystore.json",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "read keystore file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunImportKeystore_InvalidJSON(t *testing.T) {
	t.Setenv("WALLET_PASSWORD", "any-password")

	tmpDir := t.TempDir()

	file := filepath.Join(tmpDir, "invalid.json")

	err := os.WriteFile(
		file,
		[]byte(`{"invalid": json`),
		0600,
	)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	err = runImportKeystore(importKeystoreCmd, []string{file})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "unmarshal keystore JSON") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunImportKeystore_EmptyJSON(t *testing.T) {
	t.Setenv("WALLET_PASSWORD", "any-password")

	tmpDir := t.TempDir()

	file := filepath.Join(tmpDir, "empty.json")

	if err := os.WriteFile(
		file,
		[]byte(`{}`),
		0600,
	); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	err := runImportKeystore(importKeystoreCmd, []string{file})

	if err == nil {
		t.Fatal("expected decrypt error, got nil")
	}

	if !strings.Contains(err.Error(), "decrypt keystore") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunImportKeystore_RequiresExactlyOneArgument(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no arguments",
			args: nil,
		},
		{
			name: "two arguments",
			args: []string{
				"keystore1.json",
				"keystore2.json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := importKeystoreCmd.Args(importKeystoreCmd, tt.args)

			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestRunImportKeystore_ValidJSONStructure(t *testing.T) {
	t.Setenv("WALLET_PASSWORD", "any-password")

	tmpDir := t.TempDir()

	file := filepath.Join(tmpDir, "keystore.json")

	keystoreJSON := map[string]interface{}{
		"version": 3,
		"crypto":  map[string]interface{}{},
	}

	data, err := json.Marshal(keystoreJSON)
	if err != nil {
		t.Fatalf("failed to marshal test JSON: %v", err)
	}

	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	err = runImportKeystore(importKeystoreCmd, []string{file})

	if err == nil {
		t.Fatal("expected decrypt error, got nil")
	}

	if !strings.Contains(err.Error(), "decrypt keystore") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestImportKeystoreCmd_ShowPrivateDefault(t *testing.T) {
	showPrivate = false

	if showPrivate {
		t.Fatal("expected showPrivate to be false by default")
	}
}

func TestImportKeystoreCmd_ShowPrivateFlag(t *testing.T) {
	flag := importKeystoreCmd.Flags().Lookup("show-private")

	if flag == nil {
		t.Fatal("expected --show-private flag to exist")
	}

	if flag.DefValue != "false" {
		t.Fatalf(
			"expected default value false, got %q",
			flag.DefValue,
		)
	}
}
