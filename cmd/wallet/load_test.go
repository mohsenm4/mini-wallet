package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mohsenm4/mini-wallet/internal/mnemonic"
	"github.com/spf13/cobra"
)

func newLoadCmd(in string, showMnemonic bool) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("in", in, "")
	cmd.Flags().Bool("show-mnemonic", showMnemonic, "")
	return cmd
}

func newTestWalletFile(t *testing.T, password string) (path string, entropy []byte) {
	t.Helper()
	entropy, err := mnemonic.NewEntropy(128)
	if err != nil {
		t.Fatalf("generate entropy: %v", err)
	}
	path = filepath.Join(t.TempDir(), "wallet.json")
	if err := saveWallet(path, entropy, password, "0x0", true); err != nil {
		t.Fatalf("save wallet: %v", err)
	}
	return path, entropy
}

func TestRunLoad_HappyPath(t *testing.T) {
	t.Setenv("WALLET_PASSPHRASE", "")
	t.Setenv("WALLET_PASSWORD", "test-password")

	path, _ := newTestWalletFile(t, "test-password")

	if err := runLoad(newLoadCmd(path, false), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLoad_ShowMnemonic(t *testing.T) {
	t.Setenv("WALLET_PASSPHRASE", "")
	t.Setenv("WALLET_PASSWORD", "test-password")

	path, _ := newTestWalletFile(t, "test-password")

	output := captureStdout(t, func() {
		if err := runLoad(newLoadCmd(path, true), nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(output, "Mnemonic:") {
		t.Fatalf("expected mnemonic in output, got %q", output)
	}
}

func TestRunLoad_WrongPassword(t *testing.T) {
	t.Setenv("WALLET_PASSPHRASE", "")

	path, _ := newTestWalletFile(t, "test-password")

	t.Setenv("WALLET_PASSWORD", "wrong-password")

	err := runLoad(newLoadCmd(path, false), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "mac mismatch") {
		t.Fatalf("expected mac mismatch error, got: %v", err)
	}
}

func TestRunLoad_MissingFile(t *testing.T) {
	t.Setenv("WALLET_PASSPHRASE", "")
	t.Setenv("WALLET_PASSWORD", "test-password")

	err := runLoad(newLoadCmd("/path/does/not/exist.json", false), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no wallet found") {
		t.Fatalf("expected 'no wallet found' error, got: %v", err)
	}
}

func TestRunLoad_CorruptFile(t *testing.T) {
	t.Setenv("WALLET_PASSPHRASE", "")
	t.Setenv("WALLET_PASSWORD", "test-password")

	path := filepath.Join(t.TempDir(), "wallet.json")
	if err := os.WriteFile(path, []byte(`{not valid json`), 0600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	err := runLoad(newLoadCmd(path, false), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error, got: %v", err)
	}
}
