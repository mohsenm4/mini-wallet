package hd

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestNewMasterKey(t *testing.T) {
	seed, err := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f",
	)
	if err != nil {
		t.Fatal(err)
	}

	expectedKeyHex := "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
	expectedChainCodeHex := "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey returned unexpected error: %v", err)
	}

	keyHex := fmt.Sprintf("%x", masterKey.Key)
	chainCodeHex := fmt.Sprintf("%x", masterKey.ChainCode)

	if keyHex != expectedKeyHex {
		t.Errorf("Master key mismatch\ngot:  %s\nwant: %s", keyHex, expectedKeyHex)
	}

	if chainCodeHex != expectedChainCodeHex {
		t.Errorf("Chain code mismatch\ngot:  %s\nwant: %s", chainCodeHex, expectedChainCodeHex)
	}
}
