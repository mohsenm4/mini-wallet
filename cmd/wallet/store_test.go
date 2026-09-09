package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/mohsenm4/mini-wallet/internal/mnemonic"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	entropy, err := mnemonic.NewEntropy(128)
	if err != nil {
		t.Fatalf("failed to generate entropy: %v", err)
	}

	password := "testpassword"
	address := "0x1234567890abcdef"

	tmpFile := "test_wallet.json"
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	err = saveWallet(tmpFile, entropy, password, address, true)
	if err != nil {
		t.Fatalf("failed to save wallet: %v", err)
	}

	loadedEntropy, loadedAddress, err := loadWallet(tmpFile, password)
	if err != nil {
		t.Fatalf("failed to load wallet: %v", err)
	}

	if !bytes.Equal(entropy, loadedEntropy) {
		t.Errorf("loaded entropy does not match original entropy")
	}

	if loadedAddress != address {
		t.Errorf("loaded address does not match original address")
	}
}

func TestSave_NoTempFileLeft(t *testing.T) {
	entropy, err := mnemonic.NewEntropy(128)
	if err != nil {
		t.Fatalf("failed to generate entropy: %v", err)
	}

	password := "testpassword"
	address := "0x1234567890abcdef"

	tmpFile := "test_wallet.json"
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	err = saveWallet(tmpFile, entropy, password, address, true)
	if err != nil {
		t.Fatalf("failed to save wallet: %v", err)
	}

	if _, err := os.Stat(tmpFile + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temporary file %s.tmp should not exist after saving", tmpFile)
	}
}

func TestSave_RefusesOverwrite(t *testing.T) {
	entropy, err := mnemonic.NewEntropy(128)
	if err != nil {
		t.Fatalf("failed to generate entropy: %v", err)
	}

	password := "testpassword"
	address := "0x1234567890abcdef"

	tmpFile := "test_wallet.json"
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	err = saveWallet(tmpFile, entropy, password, address, true)
	if err != nil {
		t.Fatalf("failed to save wallet: %v", err)
	}

	err = saveWallet(tmpFile, entropy, password, address, false)
	if err == nil {
		t.Errorf("expected error when saving to existing file without force, got nil")
	}
}

func TestSave_ForceOverwrites(t *testing.T) {
	entropy, err := mnemonic.NewEntropy(128)
	if err != nil {
		t.Fatalf("failed to generate entropy: %v", err)
	}

	password := "testpassword"
	address := "0x1234567890abcdef"

	tmpFile := "test_wallet.json"
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	err = saveWallet(tmpFile, entropy, password, address, true)
	if err != nil {
		t.Fatalf("failed to save wallet: %v", err)
	}

	err = saveWallet(tmpFile, entropy, password, address, true)
	if err != nil {
		t.Errorf("expected successful overwrite with force, got error: %v", err)
	}
}

func TestSave_FilePerms(t *testing.T) {
	entropy, err := mnemonic.NewEntropy(128)
	if err != nil {
		t.Fatalf("failed to generate entropy: %v", err)
	}

	password := "testpassword"
	address := "0x1234567890abcdef"

	tmpFile := "test_wallet.json"
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	err = saveWallet(tmpFile, entropy, password, address, true)
	if err != nil {
		t.Fatalf("failed to save wallet: %v", err)
	}

	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("failed to stat wallet file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("expected file permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestLoad_WrongPassword(t *testing.T) {
	entropy, err := mnemonic.NewEntropy(128)
	if err != nil {
		t.Fatalf("failed to generate entropy: %v", err)
	}

	password := "testpassword"
	address := "0x1234567890abcdef"

	tmpFile := "test_wallet.json"
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	err = saveWallet(tmpFile, entropy, password, address, true)
	if err != nil {
		t.Fatalf("failed to save wallet: %v", err)
	}

	_, _, err = loadWallet(tmpFile, "wrongpassword")
	if err == nil {
		t.Errorf("expected error when loading with wrong password, got nil")
	}
}

func TestLoad_CorruptFile(t *testing.T) {
	tmpFile := "test_wallet.json"
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	err := os.WriteFile(tmpFile, []byte("invalid json"), 0600)
	if err != nil {
		t.Fatalf("failed to write corrupt wallet file: %v", err)
	}

	_, _, err = loadWallet(tmpFile, "testpassword")
	if err == nil {
		t.Errorf("expected error when loading corrupt wallet file, got nil")
	}
}
