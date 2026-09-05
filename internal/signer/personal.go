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
	hash := hashPersonalMessage(message)
	pubKey, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pubKey), nil
}
