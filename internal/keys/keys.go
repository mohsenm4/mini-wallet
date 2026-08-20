package keys

import (
	"crypto/ecdsa"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func LoadPrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(strings.TrimPrefix(hexKey, "0x"))
}

func Sign(hash []byte, prv *ecdsa.PrivateKey) ([]byte, error) {
	return crypto.Sign(hash, prv)
}

func RecoverPubkey(hash []byte, signature []byte) (*ecdsa.PublicKey, error) {
	return crypto.SigToPub(hash, signature)
}

func PublicKeyToAddress(pub *ecdsa.PublicKey) common.Address {
	return crypto.PubkeyToAddress(*pub)
}

func RecoverAddress(hash []byte, signature []byte) (common.Address, error) {
	pubkey, err := RecoverPubkey(hash, signature)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pubkey), nil
}
