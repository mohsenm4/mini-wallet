package hd

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

type PrivateKey struct {
	Key       [32]byte
	ChainCode [32]byte
}

func NewMasterKey(seed []byte) (*PrivateKey, error) {
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, _ = h.Write(seed)

	sum := h.Sum(nil)

	il := new(big.Int).SetBytes(sum[:32])
	curveN := crypto.S256().Params().N // secp256k1 order

	if il.Sign() == 0 {
		return nil, errors.New("invalid master key: IL is zero")
	}
	if il.Cmp(curveN) >= 0 {
		return nil, errors.New("invalid master key: IL >= n")
	}

	var key PrivateKey
	copy(key.Key[:], sum[:32])
	copy(key.ChainCode[:], sum[32:])

	return &key, nil
}
