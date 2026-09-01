package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mohsenm4/mini-wallet/internal/hd"
	"github.com/mohsenm4/mini-wallet/internal/keystore"
	"github.com/mohsenm4/mini-wallet/internal/mnemonic"
	"github.com/spf13/cobra"
)

var (
	exportIndex uint32
	exportOut   string
)

func init() {
	rootCmd.AddCommand(exportKeystoreCmd)
	exportKeystoreCmd.Flags().Uint32Var(&exportIndex, "index", 0, "address index for the default BIP44 path m/44'/60'/0'/0/N")
	exportKeystoreCmd.Flags().StringVar(&exportOut, "out", "", "file path to write keystore JSON (defaults to stdout)")

}

func runExportKeystore(cmd *cobra.Command, args []string) error {
	words := os.Getenv("WALLET_MNEMONIC")
	if words == "" {
		return fmt.Errorf("WALLET_MNEMONIC environment variable is not set")
	}
	passphrase := os.Getenv("WALLET_PASSPHRASE")

	password := os.Getenv("WALLET_PASSWORD")
	if password == "" {
		return fmt.Errorf("WALLET_PASSWORD environment variable is not set")
	}

	path := fmt.Sprintf("m/44'/60'/0'/0/%d", exportIndex)

	seed := mnemonic.ToSeed(words, passphrase)

	priv, err := hd.DerivePath(seed, path)
	if err != nil {
		return fmt.Errorf("derive %q: %w", path, err)
	}

	ks, err := keystore.Encrypt(priv.Key, password)
	if err != nil {
		return fmt.Errorf("encrypt keystore: %w", err)
	}

	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keystore: %w", err)
	}

	if exportOut != "" {
		if err := os.WriteFile(exportOut, data, 0600); err != nil {
			return fmt.Errorf("write keystore to file: %w", err)
		}
		fmt.Printf("Keystore exported to %s\n", exportOut)
	} else {
		fmt.Println(string(data))
	}

	return nil

}

var exportKeystoreCmd = &cobra.Command{
	Use:   "export-keystore",
	Short: "Export the keystore JSON for a given private key",
	RunE:  runExportKeystore,
}
