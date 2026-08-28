package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"

	"github.com/mohsenm4/mini-wallet/internal/hd"
	"github.com/mohsenm4/mini-wallet/internal/keys"
	"github.com/mohsenm4/mini-wallet/internal/mnemonic"
)

var (
	deriveIndex uint32
	derivePath  string
)

func init() {
	rootCmd.AddCommand(deriveCmd)
	deriveCmd.Flags().Uint32Var(&deriveIndex, "index", 0, "address index for the default BIP44 path m/44'/60'/0'/0/N")
	deriveCmd.Flags().StringVar(&derivePath, "path", "", "explicit BIP32 derivation path (e.g. m/44'/60'/0'/0/5)")
	deriveCmd.MarkFlagsMutuallyExclusive("index", "path")
}

func runDerive(cmd *cobra.Command, args []string) error {
	words := os.Getenv("WALLET_MNEMONIC")
	if words == "" {
		return fmt.Errorf("WALLET_MNEMONIC environment variable is not set")
	}
	passphrase := os.Getenv("WALLET_PASSPHRASE")

	path := derivePath
	if path == "" {
		path = fmt.Sprintf("m/44'/60'/0'/0/%d", deriveIndex)
	}

	seed := mnemonic.ToSeed(words, passphrase)

	priv, err := hd.DerivePath(seed, path)
	if err != nil {
		return fmt.Errorf("derive %q: %w", path, err)
	}

	ecdsaKey, err := crypto.ToECDSA(priv.Key[:])
	if err != nil {
		return fmt.Errorf("to ECDSA: %w", err)
	}
	address := keys.PublicKeyToAddress(&ecdsaKey.PublicKey).Hex()

	fmt.Println("Path:       ", path)
	fmt.Println("Address:    ", address)
	fmt.Println("PrivateKey: ", "0x"+hex.EncodeToString(priv.Key[:]))
	return nil
}

var deriveCmd = &cobra.Command{
	Use:   "derive",
	Short: "Derive an Ethereum address from WALLET_MNEMONIC",
	Long: `Derive an Ethereum HD wallet address from the mnemonic in
WALLET_MNEMONIC (optionally combined with WALLET_PASSPHRASE).

By default derives the first account's first external address using the
BIP44 path m/44'/60'/0'/0/0. Use --index to pick a different address at
the same account, or --path to specify an arbitrary BIP32 derivation
path.`,
	RunE: runDerive,
}
