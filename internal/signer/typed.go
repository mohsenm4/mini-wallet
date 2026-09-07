package signer

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type Field struct {
	Name string
	Type string
}

type TypedDataDomain struct {
	Name              string
	Version           string
	ChainID           *big.Int
	VerifyingContract common.Address
}

type TypedData struct {
	Types       map[string][]Field
	PrimaryType string
	Domain      TypedDataDomain
	Message     map[string]any
}

func EncodeType(primaryType string, types map[string][]Field) string {
	panic("todo")
}

func TypeHash(primaryType string, types map[string][]Field) []byte {
	panic("todo")
}

func HashStruct(primaryType string, data map[string]any, types map[string][]Field) ([]byte, error) {
	panic("todo")
}

func HashDomain(d TypedDataDomain) ([]byte, error) {
	panic("todo")
}

func SignTyped(priv *ecdsa.PrivateKey, td TypedData) ([]byte, error) {
	panic("todo")
}

func RecoverTyped(td TypedData, sig []byte) (common.Address, error) {
	panic("todo")
}
