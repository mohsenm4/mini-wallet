package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(verifyCmd)
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signed message with a public key",
	Long:  `Verify a signed message with a public key derived from a mnemonic phrase. The public key is derived using the BIP32/BIP44 standard.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO: verify message")
	},
}
