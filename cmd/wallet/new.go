package main

import (
	"fmt"

	"github.com/mohsenm4/mini-wallet/internal/mnemonic"
	"github.com/spf13/cobra"
)

var (
	newBits  int
	newSave  bool
	newForce bool
	newOut   string
)

func init() {
	rootCmd.AddCommand(newCmd)
	newCmd.Flags().IntVar(&newBits, "bits", 128, "entropy size in bits")
	newCmd.Flags().BoolVar(&newSave, "save", false, "encrypt and save the wallet to disk")
	newCmd.Flags().BoolVar(&newForce, "force", false, "overwrite an existing wallet file")
	newCmd.Flags().StringVar(&newOut, "out", "data/wallet.json", "path to write the wallet file")
}

var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Generate a new mnemonic",
	Long:  `Generate a new mnemonic phrase for an Ethereum HD wallet.`,
	RunE:  runNew,
}

func runNew(cmd *cobra.Command, args []string) error {
	entropy, err := mnemonic.NewEntropy(newBits)
	if err != nil {
		return err
	}

	words, err := mnemonic.FromEntropy(entropy)
	if err != nil {
		return err
	}

	if newSave {
		pw, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}

		addr, err := addressAtIndex(words, 0)
		if err != nil {
			return fmt.Errorf("failed to derive address: %w", err)
		}

		if err := saveWallet(newOut, entropy, pw, addr, newForce); err != nil {
			return err
		}
	}

	fmt.Println("Generated mnemonic:", words)
	if newSave {
		fmt.Println("Saved to:", newOut)
	}
	return nil
}
