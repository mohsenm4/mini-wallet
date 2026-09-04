package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mohsenm4/mini-wallet/internal/keystore"
	"github.com/spf13/cobra"
)

var showPrivate bool

func init() {
	rootCmd.AddCommand(importKeystoreCmd)
	importKeystoreCmd.Flags().BoolVar(&showPrivate, "show-private", false, "show the private key in the output")
}

func runImportKeystore(cmd *cobra.Command, args []string) error {
	keystoreFile := args[0]

	password, err := readPassword()
	if err != nil {
		return err
	}

	dataJs, err := os.ReadFile(keystoreFile)
	if err != nil {
		return fmt.Errorf("read keystore file: %w", err)
	}

	var ks keystore.KeystoreV3
	if err := json.Unmarshal(dataJs, &ks); err != nil {
		return fmt.Errorf("unmarshal keystore JSON: %w", err)
	}

	privKey, err := keystore.Decrypt(ks, password)
	if err != nil {
		return fmt.Errorf("decrypt keystore: %w", err)
	}

	ecdsaKey, err := crypto.ToECDSA(privKey)
	if err != nil {
		return fmt.Errorf("to ECDSA: %w", err)
	}
	address := crypto.PubkeyToAddress(ecdsaKey.PublicKey).Hex()

	fmt.Println("Address:     ", address)

	if showPrivate {
		fmt.Println("PrivateKey: ", "0x"+hex.EncodeToString(privKey))
	}
	return nil
}

var importKeystoreCmd = &cobra.Command{
	Use:   "import-keystore FILE",
	Short: "Import a keystore JSON file and print the Ethereum address (add --show-private to reveal the private key)",
	Args:  cobra.ExactArgs(1),
	RunE:  runImportKeystore,
}
