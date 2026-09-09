package mnemonic

import (
	"fmt"
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

func TestToSeed(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "TREZOR"
	expectedSeedHex := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"

	seed := ToSeed(mnemonic, passphrase)
	seedHex := fmt.Sprintf("%x", seed)

	if seedHex != expectedSeedHex {
		t.Errorf("ToSeed returned unexpected result:\ngot:  %s\nwant: %s", seedHex, expectedSeedHex)
	}
}

func TestNewEntropy_Lengths(t *testing.T) {
	validLengths := []int{128, 160, 192, 224, 256}
	for _, bits := range validLengths {
		entropy, err := NewEntropy(bits)
		if err != nil {
			t.Fatalf("NewEntropy(%d) returned error: %v", bits, err)
		}
		if len(entropy) != bits/8 {
			t.Errorf("NewEntropy(%d) returned %d bytes, want %d", bits, len(entropy), bits/8)
		}
	}

	invalidLengths := []int{0, 64, 100, 129, 512}
	for _, bits := range invalidLengths {
		if _, err := NewEntropy(bits); err == nil {
			t.Errorf("NewEntropy(%d) expected error for invalid length, got nil", bits)
		}
	}
}

func TestNewEntropy_InvalidBits(t *testing.T) {
	invalidBits := []int{0, 64, 100, 129, 512}
	for _, bits := range invalidBits {
		if _, err := NewEntropy(bits); err == nil {
			t.Errorf("NewEntropy(%d) expected error for invalid length, got nil", bits)
		}
	}
}

func TestNewEntropy_NotAllZeros(t *testing.T) {
	entropy, err := NewEntropy(128)
	if err != nil {
		t.Fatalf("NewEntropy returned error: %v", err)
	}
	allZeros := true
	for _, b := range entropy {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("NewEntropy returned all zeros, expected random bytes")
	}
}
