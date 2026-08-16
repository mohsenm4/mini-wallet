package mnemonic

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var validEntropyBits = map[int]bool{
	128: true,
	160: true,
	192: true,
	224: true,
	256: true,
}

func FromEntropy(entropy []byte) (string, error) {
	bits := len(entropy) * 8

	if !validEntropyBits[bits] {
		return "", fmt.Errorf("invalid entropy length: %d bits", bits)
	}

	checksumBits := bits / 32

	hash := sha256.Sum256(entropy)

	firstByteBits := fmt.Sprintf("%08b", hash[0])
	checksum := firstByteBits[:checksumBits]

	bitstring := ""
	for _, b := range entropy {
		bitstring += fmt.Sprintf("%08b", b)
	}

	bitstring += checksum

	words := []string{}

	for i := 0; i < len(bitstring); i += 11 {
		indexBits := bitstring[i : i+11]
		index := 0
		for j, bit := range indexBits {
			if bit == '1' {
				index += 1 << (10 - j)
			}
		}
		words = append(words, Wordlist[index])
	}

	return strings.Join(words, " "), nil
}

func NewMnemonic(bits int) (string, error) {

	if !validEntropyBits[bits] {
		return "", fmt.Errorf("invalid entropy length: %d bits", bits)
	}

	entropy := make([]byte, bits/8)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate random entropy: %v", err)
	}

	return FromEntropy(entropy)
}

func ValidateMnemonic(m string) error {
	words := strings.Fields(m)
	if len(words) < 12 || len(words) > 24 || len(words)%3 != 0 {
		return fmt.Errorf("invalid mnemonic length: %d words", len(words))
	}

	wordCount := len(words)

	if wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24 {
		return fmt.Errorf("invalid mnemonic length: %d words", wordCount)
	}

	bitstring := ""
	for _, wo := range words {
		idx := sort.SearchStrings(Wordlist, wo)
		if idx == len(Wordlist) || Wordlist[idx] != wo {
			return fmt.Errorf("word not in wordlist: %s", wo)
		}
		bitstring += fmt.Sprintf("%011b", idx)
	}

	entropyStr := bitstring[:len(bitstring)-len(bitstring)/33]
	claimedChecksum := bitstring[len(bitstring)-len(bitstring)/33:]

	entropyBytes := []byte{}
	for i := 0; i < len(entropyStr); i += 8 {
		val, _ := strconv.ParseUint(entropyStr[i:i+8], 2, 8)
		entropyBytes = append(entropyBytes, byte(val))
	}

	hash := sha256.Sum256(entropyBytes)
	firstByteBits := fmt.Sprintf("%08b", hash[0])
	actualChecksum := firstByteBits[:len(bitstring)/33]

	if claimedChecksum != actualChecksum {
		return fmt.Errorf("invalid checksum: got %s, want %s", claimedChecksum, actualChecksum)
	}

	return nil
}
