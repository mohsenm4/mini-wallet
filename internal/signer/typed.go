package signer

import (
	"crypto/ecdsa"
	"fmt"
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
	seen := map[string]bool{primaryType: true}
	return encodeTypeRec(primaryType, types, seen)
}

func encodeTypeRec(primaryType string, types map[string][]Field, seen map[string]bool) string {
	fields := types[primaryType]

	encodedFields := ""
	for _, field := range fields {
		encodedFields += fmt.Sprintf("%s %s,", field.Type, field.Name)
	}
	if len(encodedFields) > 0 {
		encodedFields = encodedFields[:len(encodedFields)-1]
	}

	result := fmt.Sprintf("%s(%s)", primaryType, encodedFields)

	for _, field := range fields {
		if _, ok := types[field.Type]; ok && !seen[field.Type] {
			seen[field.Type] = true
			result += encodeTypeRec(field.Type, types, seen)
		}
	}

	return result
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
