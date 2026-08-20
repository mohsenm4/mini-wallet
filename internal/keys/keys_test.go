package keys

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const testKeyHex = "4c0883a69102937d6231471b5dbb6204fe512961708279e2e7f9c8e6f7a1e5b6"

func hash32(msg string) []byte {
	return crypto.Keccak256([]byte(msg))
}

func TestLoadPrivateKey(t *testing.T) {
	cases := []struct {
		name    string
		hex     string
		wantErr bool
	}{
		{"valid without prefix", testKeyHex, false},
		{"valid with 0x prefix", "0x" + testKeyHex, false},
		{"too short", "0x1234", true},
		{"non-hex chars", "0xZZ" + testKeyHex[4:], true},
		{"empty", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := LoadPrivateKey(tc.hex)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (priv=%v)", priv)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if priv == nil {
				t.Fatalf("valid input returned nil key")
			}
		})
	}
}

func TestSignRoundTrip(t *testing.T) {
	priv, err := LoadPrivateKey(testKeyHex)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	hash := hash32("hello ethereum")

	sig, err := Sign(hash, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length = %d, want 65", len(sig))
	}

	want := PublicKeyToAddress(&priv.PublicKey)

	got, err := RecoverAddress(hash, sig)
	if err != nil {
		t.Fatalf("RecoverAddress: %v", err)
	}
	if got != want {
		t.Errorf("RecoverAddress mismatch: got %s, want %s", got.Hex(), want.Hex())
	}

	pub, err := RecoverPubkey(hash, sig)
	if err != nil {
		t.Fatalf("RecoverPubkey: %v", err)
	}
	if PublicKeyToAddress(pub) != want {
		t.Errorf("RecoverPubkey path mismatch")
	}
}

func TestPublicKeyToAddress_Deterministic(t *testing.T) {
	priv, err := LoadPrivateKey(testKeyHex)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	a := PublicKeyToAddress(&priv.PublicKey)
	b := PublicKeyToAddress(&priv.PublicKey)
	if a != b {
		t.Errorf("PublicKeyToAddress not deterministic: %s vs %s", a.Hex(), b.Hex())
	}
	if a == (common.Address{}) {
		t.Errorf("address is zero")
	}
}

func TestRecoverAddress_BadInputs(t *testing.T) {
	priv, err := LoadPrivateKey(testKeyHex)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	hash := hash32("payload")
	validSig, err := Sign(hash, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	original := PublicKeyToAddress(&priv.PublicKey)

	errCases := []struct {
		name string
		hash []byte
		sig  []byte
	}{
		{"empty sig", hash, []byte{}},
		{"nil sig", hash, nil},
		{"short sig", hash, []byte{1, 2, 3}},
		{"empty hash", []byte{}, validSig},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RecoverAddress(tc.hash, tc.sig); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}

	t.Run("tampered sig recovers different address", func(t *testing.T) {
		tampered := bytes.Clone(validSig)
		tampered[0] ^= 0xFF
		got, err := RecoverAddress(hash, tampered)
		if err == nil && got == original {
			t.Errorf("tampered sig should not recover original address")
		}
	})

	t.Run("different hash recovers different address", func(t *testing.T) {
		otherHash := hash32("different payload")
		got, err := RecoverAddress(otherHash, validSig)
		if err == nil && got == original {
			t.Errorf("different hash should not recover original address")
		}
	})
}
