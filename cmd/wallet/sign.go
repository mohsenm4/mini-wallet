package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/mohsenm4/mini-wallet/internal/keys"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) error {
	keyHex := os.Getenv("WALLET_PRIVATE_KEY")
	if keyHex == "" {
		return fmt.Errorf("WALLET_PRIVATE_KEY environment variable is not set")
	}

	priv, err := keys.LoadPrivateKey(keyHex)
	if err != nil {
		return fmt.Errorf("failed to load private key: %v", err)
	}

	hashBytes, err := hex.DecodeString(strings.TrimPrefix(args[0], "0x"))
	if err != nil {
		return fmt.Errorf("failed to decode hash: %v", err)
	}

	if len(hashBytes) != 32 {
		return fmt.Errorf("hash must be 32 bytes (64 hex characters)")
	}

	signature, err := keys.Sign(hashBytes, priv)
	if err != nil {
		return fmt.Errorf("failed to sign hash: %v", err)
	}

	fmt.Println("0x" + hex.EncodeToString(signature))
	return nil
}

var signCmd = &cobra.Command{
	Use:   "sign <hex-hash>",
	Short: "Sign a 32-byte hex hash with the WALLET_PRIVATE_KEY",
	Long: `Sign a 32-byte hex hash using the private key from the
WALLET_PRIVATE_KEY environment variable. Prints the 65-byte signature
(r || s || v) as hex.`,
	Args: cobra.ExactArgs(1),
	RunE: runSign,
}
