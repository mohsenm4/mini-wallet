package keystore

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	salt := []byte("salt")
	password := "password"
	key, err := deriveKey(password, salt)
	if err != nil {
		t.Fatalf("deriveKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected key length 32, got %d", len(key))
	}

	key2, err := deriveKey(password, salt)
	if err != nil {
		t.Fatalf("deriveKey (second call) failed: %v", err)
	}
	if !bytes.Equal(key, key2) {
		t.Fatalf("deriveKey not deterministic: %x != %x", key, key2)
	}
}

func TestKeystoreV3(t *testing.T) {
	keystore := KeystoreV3{
		Address: "0x1234567890abcdef",
		Crypto: Crypto{
			Cipher:     "aes-128-ctr",
			CipherText: "ciphertext",
			CipherParams: CipherParams{
				IV: "iv",
			},
			KDF: "scrypt",
			KDFParams: KDFParams{
				DKLen: 32,
				N:     262144,
				P:     1,
				R:     8,
				Salt:  "salt",
			},
			MAC: "mac",
		},
		ID:      "id",
		Version: 3,
	}

	if keystore.Address != "0x1234567890abcdef" {
		t.Fatalf("expected address '0x1234567890abcdef', got '%s'", keystore.Address)
	}
	if keystore.Crypto.Cipher != "aes-128-ctr" {
		t.Fatalf("expected cipher 'aes-128-ctr', got '%s'", keystore.Crypto.Cipher)
	}
	if keystore.Crypto.KDF != "scrypt" {
		t.Fatalf("expected KDF 'scrypt', got '%s'", keystore.Crypto.KDF)
	}
	if keystore.Version != 3 {
		t.Fatalf("expected version 3, got %d", keystore.Version)
	}
}

func TestEncrypt_Smoke(t *testing.T) {
	var k [32]byte
	rand.Read(k[:])
	ks, err := Encrypt(k, "pw")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", ks)
}
