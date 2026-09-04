package keystore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	ks, err := Encrypt(k[:], "pw", "0xdeadbeef")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", ks)
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	var original [32]byte
	rand.Read(original[:])

	ks, err := Encrypt(original[:], "correct-password", "0xdeadbeef")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	recovered, err := Decrypt(ks, "correct-password")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(original[:], recovered) {
		t.Fatalf("mismatch: got %x, want %x", recovered, original)
	}
}

func TestDecrypt_WrongPassword(t *testing.T) {
	var k [32]byte
	rand.Read(k[:])

	ks, _ := Encrypt(k[:], "correct", "0xdeadbeef")
	_, err := Decrypt(ks, "WRONG")

	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestDecrypt_ReferenceVector(t *testing.T) {

	keystoreJSON := `{
    "crypto": {
        "cipher": "aes-128-ctr",
        "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
        "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
        "kdf": "scrypt",
        "kdfparams": {
            "dklen": 32,
            "n": 262144,
            "p": 8,
            "r": 1,
            "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
        },
        "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
    },
    "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "version": 3
}`

	password := "testpassword"
	expectedKeyHex := "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"

	var ks KeystoreV3
	if err := json.Unmarshal([]byte(keystoreJSON), &ks); err != nil {
		t.Fatalf("failed to unmarshal keystore JSON: %v", err)
	}

	// Replace "correct-password" with the actual password for the reference vector.
	recovered, err := Decrypt(ks, password)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	expected, _ := hex.DecodeString(expectedKeyHex)
	if !bytes.Equal(recovered[:], expected) {
		t.Fatalf("mismatch: got %x, want %s", recovered, expectedKeyHex)
	}

}
