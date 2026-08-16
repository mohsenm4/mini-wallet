package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(signCmd)
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a message with a private key",
	Long:  `Sign a message with a private key derived from a mnemonic phrase. The private key is derived using the BIP32/BIP44 standard.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO: sign message")
	},
}
