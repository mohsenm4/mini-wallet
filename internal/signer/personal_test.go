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

func TestRecoverPersonal_AcceptsBothVFormats(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	message := []byte("Hello, Ethereum!")
	sig, err := SignPersonal(privKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}
	if v := sig[64]; v != 0 && v != 1 {
		t.Fatalf("Unexpected v from SignPersonal: %d (want 0 or 1)", v)
	}

	expectedAddr := crypto.PubkeyToAddress(privKey.PublicKey)

	addrRaw, err := RecoverPersonal(message, sig)
	if err != nil {
		t.Fatalf("Recover with v=%d failed: %v", sig[64], err)
	}
	if addrRaw != expectedAddr {
		t.Errorf("v=%d recovered %s, want %s", sig[64], addrRaw.Hex(), expectedAddr.Hex())
	}

	walletSig := append([]byte(nil), sig...)
	walletSig[64] += 27
	addrWallet, err := RecoverPersonal(message, walletSig)
	if err != nil {
		t.Fatalf("Recover with v=%d failed: %v", walletSig[64], err)
	}
	if addrWallet != expectedAddr {
		t.Errorf("v=%d recovered %s, want %s", walletSig[64], addrWallet.Hex(), expectedAddr.Hex())
	}

	if sig[64] >= 27 {
		t.Error("RecoverPersonal mutated caller's signature slice")
	}
}

func TestRecoverPersonal_InvalidLength(t *testing.T) {
	if _, err := RecoverPersonal([]byte("msg"), []byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for short signature, got nil")
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
