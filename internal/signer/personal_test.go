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

func TestRecoverPersonal_WrongSigner(t *testing.T) {
	signerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate signer key: %v", err)
	}
	otherKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate other key: %v", err)
	}

	message := []byte("Hello, Ethereum!")
	sig, err := SignPersonal(signerKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	recoveredAddr, err := RecoverPersonal(message, sig)
	if err != nil {
		t.Fatalf("Failed to recover address: %v", err)
	}

	otherAddr := crypto.PubkeyToAddress(otherKey.PublicKey)
	if recoveredAddr == otherAddr {
		t.Errorf("Recovered address unexpectedly matches other signer %s", otherAddr.Hex())
	}
}

func TestRecoverPersonal_TamperedMessage(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	message := []byte("Hello, Ethereum!")
	sig, err := SignPersonal(privKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	tampered := []byte("Hello, Ethereum?")
	recoveredAddr, err := RecoverPersonal(tampered, sig)
	if err != nil {
		t.Fatalf("Failed to recover address from tampered message: %v", err)
	}

	signerAddr := crypto.PubkeyToAddress(privKey.PublicKey)
	if recoveredAddr == signerAddr {
		t.Errorf("Recovered signer from tampered message — signature should not verify")
	}
}
