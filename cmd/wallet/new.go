package main

import (
	"fmt"

	"github.com/mohsenm4/mini-wallet/internal/mnemonic"
	"github.com/spf13/cobra"
)

var newBits int

func init() {
	rootCmd.AddCommand(newCmd)
	newCmd.Flags().IntVar(&newBits, "bits", 128, "entropy size in bits")
}

var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Generate a new mnemonic",
	Long:  `Generate a new mnemonic phrase for an Ethereum HD wallet.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := mnemonic.NewMnemonic(newBits)
		if err != nil {
			return err
		}
		fmt.Println("Generated mnemonic:", m)
		return nil
	},
}
