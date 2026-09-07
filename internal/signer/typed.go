package signer

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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
	encodedType := EncodeType(primaryType, types)
	return crypto.Keccak256([]byte(encodedType))
}

func HashStruct(primaryType string, data map[string]any, types map[string][]Field) ([]byte, error) {
	hashtype := TypeHash(primaryType, types)
	encodedData := []byte{}
	for _, field := range types[primaryType] {
		value, ok := data[field.Name]
		if !ok {
			return nil, fmt.Errorf("missing value for field %s", field.Name)
		}

		var encodedValue []byte
		switch field.Type {
		case "string":
			str, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("field %s must be string", field.Name)
			}
			encodedValue = crypto.Keccak256([]byte(str))
		case "uint256":
			bigIntValue, ok := value.(*big.Int)
			if !ok {
				return nil, fmt.Errorf("field %s must be *big.Int", field.Name)
			}
			encodedValue = common.LeftPadBytes(bigIntValue.Bytes(), 32)
		case "address":
			var addr common.Address
			switch v := value.(type) {
			case common.Address:
				addr = v
			case string:
				addr = common.HexToAddress(v)
			default:
				return nil, fmt.Errorf("field %s must be address string or common.Address", field.Name)
			}
			encodedValue = common.LeftPadBytes(addr.Bytes(), 32)
		default:
			if _, ok := types[field.Type]; ok {
				nestedHash, err := HashStruct(field.Type, value.(map[string]any), types)
				if err != nil {
					return nil, err
				}
				encodedValue = nestedHash
			} else {
				return nil, fmt.Errorf("unsupported type: %s", field.Type)
			}
		}
		encodedData = append(encodedData, encodedValue...)
	}

	finalData := append(hashtype, encodedData...)
	return crypto.Keccak256(finalData), nil
}

func HashDomain(d TypedDataDomain) ([]byte, error) {
	data := map[string]any{
		"name":              d.Name,
		"version":           d.Version,
		"chainId":           d.ChainID,
		"verifyingContract": d.VerifyingContract,
	}
	types := map[string][]Field{
		"EIP712Domain": {
			{"name", "string"},
			{"version", "string"},
			{"chainId", "uint256"},
			{"verifyingContract", "address"},
		},
	}
	return HashStruct("EIP712Domain", data, types)
}

func SignTyped(priv *ecdsa.PrivateKey, td TypedData) ([]byte, error) {
	domainHash, err := HashDomain(td.Domain)
	if err != nil {
		return nil, err
	}

	messageHash, err := HashStruct(td.PrimaryType, td.Message, td.Types)
	if err != nil {
		return nil, err
	}

	data := append([]byte("\x19\x01"), domainHash...)
	data = append(data, messageHash...)

	return crypto.Sign(crypto.Keccak256(data), priv)

}

func RecoverTyped(td TypedData, sig []byte) (common.Address, error) {

	domainHash, err := HashDomain(td.Domain)
	if err != nil {
		return common.Address{}, err
	}

	messageHash, err := HashStruct(td.PrimaryType, td.Message, td.Types)
	if err != nil {
		return common.Address{}, err
	}

	data := append([]byte("\x19\x01"), domainHash...)
	data = append(data, messageHash...)

	pubKey, err := crypto.SigToPub(crypto.Keccak256(data), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pubKey), nil

}
