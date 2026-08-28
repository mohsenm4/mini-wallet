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

func TestChild(t *testing.T) {
	seed, err := hex.DecodeString(
		"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
	)
	if err != nil {
		t.Fatal(err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey returned unexpected error: %v", err)
	}

	childIndex := uint32(0)
	childKey, err := masterKey.Child(childIndex)
	if err != nil {
		t.Fatalf("Child returned unexpected error: %v", err)
	}

	expectedChildKeyHex := "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
	expectedChildChainCodeHex := "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"

	childKeyHex := fmt.Sprintf("%x", childKey.Key)
	childChainCodeHex := fmt.Sprintf("%x", childKey.ChainCode)

	if childKeyHex != expectedChildKeyHex {
		t.Errorf("Child key mismatch\ngot:  %s\nwant: %s", childKeyHex, expectedChildKeyHex)
	}

	if childChainCodeHex != expectedChildChainCodeHex {
		t.Errorf("Child chain code mismatch\ngot:  %s\nwant: %s", childChainCodeHex, expectedChildChainCodeHex)
	}
}

func TestChildChain(t *testing.T) {
	seed, err := hex.DecodeString(
		"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
	)
	if err != nil {
		t.Fatal(err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey returned unexpected error: %v", err)
	}

	c0, err := masterKey.Child(0)
	if err != nil {
		t.Fatalf("Child(0) returned unexpected error: %v", err)
	}
	c01, err := c0.Child(1)
	if err != nil {
		t.Fatalf("Child(1) returned unexpected error: %v", err)
	}

	expectedKeyHex := "fb1e5b0be9e72c9e158b33ad5d68c59e6d5b853ec56beb0b7ee1c13e5e200e47"
	expectedChainCodeHex := "8d5e25bfe038e4ef37e2c5ec963b7a7c7a745b4319bff873fc40f1a52c7d6fd1"

	keyHex := fmt.Sprintf("%x", c01.Key)
	chainCodeHex := fmt.Sprintf("%x", c01.ChainCode)

	if keyHex != expectedKeyHex {
		t.Errorf("m/0/1 key mismatch\ngot:  %s\nwant: %s", keyHex, expectedKeyHex)
	}

	if chainCodeHex != expectedChainCodeHex {
		t.Errorf("m/0/1 chain code mismatch\ngot:  %s\nwant: %s", chainCodeHex, expectedChainCodeHex)
	}
}

func TestChildHardened(t *testing.T) {
	seed, err := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f",
	)
	if err != nil {
		t.Fatal(err)
	}

	masterKey, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey returned unexpected error: %v", err)
	}

	childIndex := uint32(HardenedOffset + 0) // Hardened child index
	childKey, err := masterKey.Child(childIndex)
	if err != nil {
		t.Fatalf("Child returned unexpected error: %v", err)
	}

	expectedChildKeyHex := "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
	expectedChildChainCodeHex := "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"

	childKeyHex := fmt.Sprintf("%x", childKey.Key)
	childChainCodeHex := fmt.Sprintf("%x", childKey.ChainCode)

	if childKeyHex != expectedChildKeyHex {
		t.Errorf("Hardened child key mismatch\ngot:  %s\nwant: %s", childKeyHex, expectedChildKeyHex)
	}

	if childChainCodeHex != expectedChildChainCodeHex {
		t.Errorf("Hardened child chain code mismatch\ngot:  %s\nwant: %s", childChainCodeHex, expectedChildChainCodeHex)
	}
}
