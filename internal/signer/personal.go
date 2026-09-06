package signer

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func hashPersonalMessage(message []byte) common.Hash {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))

	data := append([]byte(prefix), message...)
	return crypto.Keccak256Hash(data)
}

func SignPersonal(privKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := hashPersonalMessage(message)
	sig, err := crypto.Sign(hash.Bytes(), privKey)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func RecoverPersonal(message, sig []byte) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("invalid signature length: got %d bytes, want 65", len(sig))
	}

	// Wallets (MetaMask, ethers) emit v as 27/28 per EIP-191, but go-ethereum's
	// SigToPub expects 0/1. Accept either without mutating the caller's slice.
	normalised := sig
	if v := sig[64]; v == 27 || v == 28 {
		normalised = make([]byte, 65)
		copy(normalised, sig)
		normalised[64] = v - 27
	}

	hash := hashPersonalMessage(message)
	pubKey, err := crypto.SigToPub(hash.Bytes(), normalised)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pubKey), nil
}
