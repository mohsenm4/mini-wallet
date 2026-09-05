package hd

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

const HardenedOffset uint32 = 0x80000000

type PrivateKey struct {
	Key       [32]byte
	ChainCode [32]byte
}

func NewMasterKey(seed []byte) (*PrivateKey, error) {
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, _ = h.Write(seed)

	sum := h.Sum(nil)

	left := new(big.Int).SetBytes(sum[:32])
	curveN := crypto.S256().Params().N // secp256k1 order

	if left.Sign() == 0 {
		return nil, errors.New("invalid master key: left half is zero")
	}
	if left.Cmp(curveN) >= 0 {
		return nil, errors.New("invalid master key: left half >= curve order")
	}

	var key PrivateKey
	copy(key.Key[:], sum[:32])
	copy(key.ChainCode[:], sum[32:])

	return &key, nil
}

func (k *PrivateKey) Child(i uint32) (*PrivateKey, error) {

	pvk, err := crypto.ToECDSA(k.Key[:])
	if err != nil {
		return nil, err
	}

	data := make([]byte, 37)
	if i >= HardenedOffset {
		data[0] = 0x00
		copy(data[1:33], k.Key[:])
	} else {
		serP := crypto.CompressPubkey(&pvk.PublicKey)
		copy(data[:33], serP)
	}
	binary.BigEndian.PutUint32(data[33:], i)

	h := hmac.New(sha512.New, k.ChainCode[:])
	_, _ = h.Write(data)
	sum := h.Sum(nil)

	left := new(big.Int).SetBytes(sum[:32])
	right := sum[32:]
	curveN := crypto.S256().Params().N // secp256k1 order

	if left.Cmp(curveN) >= 0 {
		return nil, errors.New("invalid child key: left half >= curve order")
	}

	childKey := new(big.Int).Add(left, new(big.Int).SetBytes(k.Key[:]))
	childKey.Mod(childKey, curveN)

	if childKey.Sign() == 0 {
		return nil, errors.New("invalid child key: derived key is zero")
	}

	var child PrivateKey
	childKey.FillBytes(child.Key[:])
	copy(child.ChainCode[:], right)

	return &child, nil
}
