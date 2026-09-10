package main

import (
	"strings"
	"testing"
)

func TestRunSign_WithoutPrivateKey(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", "")

	cmd := signCmd
	err := runSign(cmd, []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "WALLET_PRIVATE_KEY environment variable is not set") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunSign_InvalidPrivateKey(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", "invalid-private-key")

	err := runSign(signCmd, []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to load private key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunSign_InvalidHashHex(t *testing.T) {
	// این کلید باید برای LoadPrivateKey معتبر باشد.
	t.Setenv(
		"WALLET_PRIVATE_KEY",
		"0000000000000000000000000000000000000000000000000000000000000001",
	)

	err := runSign(signCmd, []string{
		"not-hex",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to decode hash") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunSign_InvalidHashLength(t *testing.T) {
	t.Setenv(
		"WALLET_PRIVATE_KEY",
		"0000000000000000000000000000000000000000000000000000000000000001",
	)

	tests := []struct {
		name string
		hash string
	}{
		{
			name: "empty",
			hash: "",
		},
		{
			name: "too short",
			hash: "00000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name: "too long",
			hash: "000000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runSign(signCmd, []string{tt.hash})

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), "hash must be 32 bytes") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunSign_With0xPrefix(t *testing.T) {
	t.Setenv(
		"WALLET_PRIVATE_KEY",
		"0000000000000000000000000000000000000000000000000000000000000001",
	)

	hash := "0000000000000000000000000000000000000000000000000000000000000000"

	err := runSign(signCmd, []string{"0x" + hash})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestRunSign_Without0xPrefix(t *testing.T) {
	t.Setenv(
		"WALLET_PRIVATE_KEY",
		"0000000000000000000000000000000000000000000000000000000000000001",
	)

	hash := "0000000000000000000000000000000000000000000000000000000000000000"

	err := runSign(signCmd, []string{hash})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestSignCmd_RequiresExactlyOneArgument(t *testing.T) {
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
			args: []string{"hash1", "hash2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := signCmd.Args(signCmd, tt.args)

			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
