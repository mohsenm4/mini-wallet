package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

func newUUIDv4() (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", err
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]), nil
}

func addressFromPrivKey(privKey [32]byte) (string, error) {
	ecdsaKey, err := crypto.ToECDSA(privKey[:])
	if err != nil {
		return "", err
	}
	addr := crypto.PubkeyToAddress(ecdsaKey.PublicKey)
	return hex.EncodeToString(addr[:]), nil
}

type KeystoreV3 struct {
	Address string `json:"address"`
	Crypto  Crypto `json:"crypto"`
	ID      string `json:"id"`
	Version int    `json:"version"`
}

type Crypto struct {
	Cipher       string       `json:"cipher"`
	CipherText   string       `json:"ciphertext"`
	CipherParams CipherParams `json:"cipherparams"`
	KDF          string       `json:"kdf"`
	KDFParams    KDFParams    `json:"kdfparams"`
	MAC          string       `json:"mac"`
}

type CipherParams struct {
	IV string `json:"iv"`
}

type KDFParams struct {
	DKLen int    `json:"dklen"`
	N     int    `json:"n"`
	P     int    `json:"p"`
	R     int    `json:"r"`
	Salt  string `json:"salt"`
}

func deriveKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 1<<18, 8, 1, 32)
}

func Encrypt(privKey [32]byte, password string) (KeystoreV3, error) {

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return KeystoreV3{}, err
	}

	derivedKey, err := deriveKey(password, salt)
	if err != nil {
		return KeystoreV3{}, err
	}

	encKey := derivedKey[:16]
	macKey := derivedKey[16:32]

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return KeystoreV3{}, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return KeystoreV3{}, err
	}
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, 32)
	stream.XORKeyStream(ciphertext, privKey[:])

	h := sha3.NewLegacyKeccak256() // golang.org/x/crypto/sha3
	h.Write(macKey)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	id, err := newUUIDv4()
	if err != nil {
		return KeystoreV3{}, err
	}

	address, err := addressFromPrivKey(privKey)
	if err != nil {
		return KeystoreV3{}, err
	}

	return KeystoreV3{
		Version: 3,
		ID:      id,
		Address: address,
		Crypto: Crypto{
			Cipher:       "aes-128-ctr",
			CipherText:   hex.EncodeToString(ciphertext),
			CipherParams: CipherParams{IV: hex.EncodeToString(iv)},
			KDF:          "scrypt",
			KDFParams: KDFParams{
				DKLen: 32, N: 262144, R: 8, P: 1,
				Salt: hex.EncodeToString(salt),
			},
			MAC: hex.EncodeToString(mac),
		},
	}, nil

}
