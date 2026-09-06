package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/mohsenm4/mini-wallet/internal/keys"
	"github.com/mohsenm4/mini-wallet/internal/signer"
	"github.com/spf13/cobra"
)

var (
	signMsgType string
	signMsgHex  bool
)

var signMessageCmd = &cobra.Command{
	Use:   "sign-message <message>",
	Short: "Sign a message the way wallets do (EIP-191 personal_sign)",
	Args:  cobra.ExactArgs(1),
	RunE:  runSignMessage,
}

func init() {
	signMessageCmd.Flags().StringVar(&signMsgType, "type", "personal", "signing scheme: personal")
	signMessageCmd.Flags().BoolVar(&signMsgHex, "hex", false, "treat <message> as hex-encoded bytes")
	rootCmd.AddCommand(signMessageCmd)
}

func runSignMessage(cmd *cobra.Command, args []string) error {
	msg, err := parseMessage(args[0], signMsgHex)
	if err != nil {
		return err
	}

	keyHex := os.Getenv("WALLET_PRIVATE_KEY")
	if keyHex == "" {
		return fmt.Errorf("WALLET_PRIVATE_KEY environment variable is not set")
	}

	privateKey, err := keys.LoadPrivateKey(keyHex)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	var sig []byte
	switch signMsgType {
	case "personal":
		sig, err = signer.SignPersonal(privateKey, msg)
		if err != nil {
			return fmt.Errorf("sign personal message: %w", err)
		}
	default:
		return fmt.Errorf("unsupported --type %q", signMsgType)
	}

	if len(sig) != 65 {
		return fmt.Errorf("invalid signature length: got %d bytes, want 65", len(sig))
	}

	if sig[64] == 0 || sig[64] == 1 {
		sig[64] += 27
	} else if sig[64] != 27 && sig[64] != 28 {
		return fmt.Errorf("invalid signature recovery id: %d", sig[64])
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), "0x"+hex.EncodeToString(sig)); err != nil {
		return err
	}

	return nil
}

func parseMessage(input string, asHex bool) ([]byte, error) {
	if !asHex {
		return []byte(input), nil
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid hex message: %w", err)
	}
	return decoded, nil
}
