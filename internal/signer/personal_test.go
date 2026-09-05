package signer

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestHashPersonalMessage(t *testing.T) {
	message := []byte("Hello, Ethereum!")
	expected := accounts.TextHash(message)

	hash := hashPersonalMessage(message)
	if !bytes.Equal(hash.Bytes(), expected) {
		t.Errorf("Expected hash %s, but got %s", expected, hash.Hex())
	}
}
func TestSignAndRecoverPersonal(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	message := []byte("Hello, Ethereum!")
	sig, err := SignPersonal(privKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	recoveredAddr, err := RecoverPersonal(message, sig)
	if err != nil {
		t.Fatalf("Failed to recover address: %v", err)
	}

	expectedAddr := crypto.PubkeyToAddress(privKey.PublicKey)
	if recoveredAddr != expectedAddr {
		t.Errorf("Expected address %s, but got %s", expectedAddr.Hex(), recoveredAddr.Hex())
	}
}
