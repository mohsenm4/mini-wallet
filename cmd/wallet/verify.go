package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mohsenm4/mini-wallet/internal/keys"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	sigHex := args[0]
	hashHex := args[1]

	sigBytes, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	if len(sigBytes) != 65 {
		return fmt.Errorf("signature must be 65 bytes (130 hex characters)")
	}

	hashBytes, err := hex.DecodeString(strings.TrimPrefix(hashHex, "0x"))
	if err != nil {
		return fmt.Errorf("failed to decode hash: %v", err)
	}

	if len(hashBytes) != 32 {
		return fmt.Errorf("hash must be 32 bytes (64 hex characters)")
	}

	address, err := keys.RecoverAddress(hashBytes, sigBytes)
	if err != nil {
		return fmt.Errorf("failed to recover address: %v", err)
	}

	fmt.Println("Recovered address:", address.Hex())
	return nil
}

var verifyCmd = &cobra.Command{
	Use:   "verify <hex-sig> <hex-hash>",
	Short: "Recover the Ethereum address from a signature and hash",
	Long: `Recover the Ethereum address from a 65-byte signature and 32-byte
hash using ECDSA public key recovery (Ecrecover).`,
	Args: cobra.ExactArgs(2),
	RunE: runVerify,
}
