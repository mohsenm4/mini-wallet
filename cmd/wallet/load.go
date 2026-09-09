package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mohsenm4/mini-wallet/internal/hd"
	"github.com/mohsenm4/mini-wallet/internal/keys"
	"github.com/mohsenm4/mini-wallet/internal/mnemonic"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(loadCmd)
	loadCmd.Flags().String("in", "data/wallet.json", "path to the wallet file")
	loadCmd.Flags().Bool("show-mnemonic", false, "print the mnemonic phrase (dangerous)")

}

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load the saved wallet and show its first address",
	Args:  cobra.NoArgs,
	RunE:  runLoad,
}

func runLoad(cmd *cobra.Command, args []string) error {

	pw, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	in, _ := cmd.Flags().GetString("in")
	showMnemonic, _ := cmd.Flags().GetBool("show-mnemonic")

	entropy, _, err := loadWallet(in, pw)
	if err != nil {
		return fmt.Errorf("failed to load wallet: %w", err)
	}

	words, err := mnemonic.FromEntropy(entropy)
	if err != nil {
		return fmt.Errorf("wallet file contains invalid entropy: %w", err)
	}

	addr, err := addressAtIndex(words, 0)
	if err != nil {
		return fmt.Errorf("failed to derive address: %w", err)
	}

	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Address: %s\n", addr); err != nil {
		return err
	}

	if showMnemonic {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Mnemonic: %s\n", words); err != nil {
			return err
		}
	}

	return nil
}

func addressAtIndex(words string, index uint32) (string, error) {
	seed := mnemonic.ToSeed(words, "")
	priv, err := hd.DerivePath(seed, fmt.Sprintf("m/44'/60'/0'/0/%d", index))
	if err != nil {
		return "", fmt.Errorf("derive address at index %d: %w", index, err)
	}

	ecdsaKey, err := crypto.ToECDSA(priv.Key[:])
	if err != nil {
		return "", fmt.Errorf("to ECDSA: %w", err)
	}
	address := keys.PublicKeyToAddress(&ecdsaKey.PublicKey).Hex()

	return address, nil
}
