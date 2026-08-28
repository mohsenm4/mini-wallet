package hd_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/mohsenm4/mini-wallet/internal/hd"
	"github.com/mohsenm4/mini-wallet/internal/keys"
	"github.com/mohsenm4/mini-wallet/internal/mnemonic"
)

// TestDerivePath_EthereumAddress exercises the full wallet pipeline
// (mnemonic -> seed -> master -> BIP44 derivation -> Ethereum address)
// against the reference vector used by MetaMask, MyEtherWallet, Trezor
// and Ledger. If this test passes the entire crypto stack is
// byte-compatible with mainstream Ethereum wallets.
func TestDerivePath_EthereumAddress(t *testing.T) {
	const (
		words      = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		passphrase = ""
	)

	tests := []struct {
		path        string
		wantAddress string
	}{
		{
			path:        "m/44'/60'/0'/0/0",
			wantAddress: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
		},
	}

	seed := mnemonic.ToSeed(words, passphrase)

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			priv, err := hd.DerivePath(seed, tt.path)
			if err != nil {
				t.Fatalf("DerivePath(%q): %v", tt.path, err)
			}

			ecdsaKey, err := crypto.ToECDSA(priv.Key[:])
			if err != nil {
				t.Fatalf("ToECDSA: %v", err)
			}

			got := keys.PublicKeyToAddress(&ecdsaKey.PublicKey).Hex()
			if got != tt.wantAddress {
				t.Errorf("address mismatch\n got:  %s\nwant: %s", got, tt.wantAddress)
			}
		})
	}
}

// TestDerivePath_PassphraseChangesAddress verifies that changing the
// BIP39 passphrase produces a completely different address — the
// passphrase is part of the seed derivation and must propagate through
// the whole pipeline.
func TestDerivePath_PassphraseChangesAddress(t *testing.T) {
	const (
		words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		path  = "m/44'/60'/0'/0/0"
	)

	seedA := mnemonic.ToSeed(words, "")
	seedB := mnemonic.ToSeed(words, "TREZOR")

	privA, err := hd.DerivePath(seedA, path)
	if err != nil {
		t.Fatalf("DerivePath (no passphrase): %v", err)
	}
	privB, err := hd.DerivePath(seedB, path)
	if err != nil {
		t.Fatalf("DerivePath (TREZOR passphrase): %v", err)
	}

	if privA.Key == privB.Key {
		t.Errorf("expected different keys for different passphrases, got identical")
	}
}
