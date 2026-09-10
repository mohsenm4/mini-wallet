package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestRunVerify_InvalidSignatureHex(t *testing.T) {
	hash := "0000000000000000000000000000000000000000000000000000000000000000"

	err := runVerify(verifyCmd, []string{
		"not-hex",
		hash,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to decode signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunVerify_InvalidSignatureLength(t *testing.T) {
	hash := "0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name string
		sig  string
	}{
		{
			name: "empty",
			sig:  "",
		},
		{
			name: "too short",
			sig:  strings.Repeat("00", 64),
		},
		{
			name: "too long",
			sig:  strings.Repeat("00", 66),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runVerify(verifyCmd, []string{
				tt.sig,
				hash,
			})

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), "signature must be 65 bytes") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunVerify_InvalidHashHex(t *testing.T) {
	// 65-byte signature
	sig := strings.Repeat("00", 65)

	err := runVerify(verifyCmd, []string{
		sig,
		"not-hex",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to decode hash") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunVerify_InvalidHashLength(t *testing.T) {
	sig := strings.Repeat("00", 65)

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
			hash: strings.Repeat("00", 31),
		},
		{
			name: "too long",
			hash: strings.Repeat("00", 33),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runVerify(verifyCmd, []string{
				sig,
				tt.hash,
			})

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), "hash must be 32 bytes") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunVerify_RequiresExactlyTwoArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no arguments",
			args: nil,
		},
		{
			name: "one argument",
			args: []string{"signature"},
		},
		{
			name: "three arguments",
			args: []string{"signature", "hash", "extra"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyCmd.Args(verifyCmd, tt.args)

			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestRunVerify_ZeroSignatureAndHash(t *testing.T) {
	sig := strings.Repeat("00", 65)
	hash := strings.Repeat("00", 32)

	err := runVerify(verifyCmd, []string{
		sig,
		hash,
	})

	if err == nil {
		t.Fatal("expected recovery error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to recover address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunVerify_With0xPrefix(t *testing.T) {
	sig := "0x" + strings.Repeat("00", 65)
	hash := "0x" + strings.Repeat("00", 32)

	err := runVerify(verifyCmd, []string{
		sig,
		hash,
	})

	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}

	if !strings.Contains(err.Error(), "failed to recover address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunVerify_Output(t *testing.T) {
	t.Skip("requires a valid signature/hash pair")
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	os.Stdout = w

	defer func() {
		os.Stdout = old
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	var buf bytes.Buffer

	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read stdout: %v", err)
	}

	if err := r.Close(); err != nil {
		t.Fatalf("failed to close reader: %v", err)
	}

	return buf.String()
}
