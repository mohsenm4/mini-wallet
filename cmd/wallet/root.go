package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "wallet",
	Short: "Ethereum HD wallet CLI",
	Long: `mini-wallet is a CLI for generating mnemonics, deriving HD keys,
and signing/verifying messages. Built for learning BIP39/BIP32/BIP44 and ECDSA.`,
}
