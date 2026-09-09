package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/mohsenm4/mini-wallet/internal/keystore"
)

func saveWallet(path string, entropy []byte, password, address string, force bool) error {

	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("file %s already exists, use --force to overwrite", path)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("failed to check wallet file: %w", err)
		}

	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create wallet directorye: %w", err)
	}

	encrypted, err := keystore.Encrypt(entropy, password, address)
	if err != nil {
		return fmt.Errorf("failed to encrypt entropy: %w", err)
	}

	b, err := json.MarshalIndent(encrypted, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted data: %w", err)
	}

	tmp := path + ".tmp"

	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return fmt.Errorf("failed to write wallet file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to move wallet file into place: %w", err)
	}

	return nil
}

func loadWallet(path, password string) (entropy []byte, storedAddr string, err error) {

	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("no wallet found at %s — run 'wallet new --save' first", path)
		}
		return nil, "", fmt.Errorf("failed to read wallet file: %w", err)
	}

	var encrypted keystore.KeystoreV3
	if err := json.Unmarshal(b, &encrypted); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal wallet file: %w", err)
	}

	entropy, err = keystore.Decrypt(encrypted, password)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt wallet file: %w", err)
	}

	return entropy, encrypted.Address, nil
}
