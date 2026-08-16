package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(newCmd)
}

var newCmd = &cobra.Command{
	Use:   "new",
	Short: "Generate a new mnemonic",
	Long:  `Generate a new mnemonic phrase for an Ethereum HD wallet.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO: generate mnemonic")
	},
}
