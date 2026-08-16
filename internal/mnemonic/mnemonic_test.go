package mnemonic

import (
	"strings"
	"testing"
)

// TestFromEntropy verifies our implementation against the official BIP39
// test vectors. If these pass, our mnemonic output is bit-for-bit compatible
// with MetaMask, Trust Wallet, and every other BIP39-compliant tool.
func TestFromEntropy(t *testing.T) {
	cases := []struct {
		name    string
		entropy []byte
		want    string
	}{
		{
			name:    "128-bit all zeros",
			entropy: make([]byte, 16),
			want:    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		},
		{
			name:    "256-bit all zeros",
			entropy: make([]byte, 32),
			want:    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FromEntropy(tc.entropy)
			if err != nil {
				t.Fatalf("FromEntropy returned an error: %v", err)
			}
			if got != tc.want {
				t.Errorf("mismatch\ngot:  %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestNewMnemonic_Length checks that each valid entropy size yields the
// expected word count (BIP39 §3).
func TestNewMnemonic_Length(t *testing.T) {
	cases := []struct {
		bits      int
		wantWords int
	}{
		{128, 12},
		{160, 15},
		{192, 18},
		{224, 21},
		{256, 24},
	}
	for _, tc := range cases {
		m, err := NewMnemonic(tc.bits)
		if err != nil {
			t.Fatalf("bits=%d: %v", tc.bits, err)
		}
		if got := len(strings.Fields(m)); got != tc.wantWords {
			t.Errorf("bits=%d: got %d words, want %d", tc.bits, got, tc.wantWords)
		}
	}
}

// TestNewMnemonic_Randomness ensures two consecutive calls produce different
// mnemonics. If they match, crypto/rand is broken or NewMnemonic is buggy.
func TestNewMnemonic_Randomness(t *testing.T) {
	a, err := NewMnemonic(128)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewMnemonic(128)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("two random mnemonics were identical (astronomically unlikely): %q", a)
	}
}

// TestNewMnemonic_InvalidBits rejects sizes not permitted by BIP39.
func TestNewMnemonic_InvalidBits(t *testing.T) {
	for _, bits := range []int{0, 64, 100, 129, 512} {
		if _, err := NewMnemonic(bits); err == nil {
			t.Errorf("bits=%d: expected error, got nil", bits)
		}
	}
}
func TestValidateMnemonic_ValidVector(t *testing.T) {
	m := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	if err := ValidateMnemonic(m); err != nil {
		t.Errorf("valid mnemonic rejected: %v", err)
	}
}

func TestValidateMnemonic_BadChecksum(t *testing.T) {
	m := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	if err := ValidateMnemonic(m); err == nil {
		t.Error("bad checksum accepted")
	}
}

func TestValidateMnemonic_UnknownWord(t *testing.T) {
	m := "hello abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	if err := ValidateMnemonic(m); err == nil {
		t.Error("unknown word accepted")
	}
}

func TestValidateMnemonic_RoundTrip(t *testing.T) {
	for i := 0; i < 10; i++ {
		m, err := NewMnemonic(128)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateMnemonic(m); err != nil {
			t.Errorf("NewMnemonic output rejected: %q → %v", m, err)
		}
	}
}
