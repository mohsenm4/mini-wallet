package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/mohsenm4/mini-wallet/internal/signer"
	"github.com/spf13/cobra"
)

var (
	verifyMsgType string
	verifyMsgHex  bool
	verifyAddress string
)

var verifyMessageCmd = &cobra.Command{
	Use:   "verify-message <message> <0x-signature>",
	Short: "Verify a message the way wallets do (EIP-191 personal_sign)",
	Args:  cobra.ExactArgs(2),
	RunE:  runVerifyMessage,
}

func init() {
	verifyMessageCmd.Flags().StringVar(&verifyMsgType, "type", "personal", "signing scheme: personal")
	verifyMessageCmd.Flags().BoolVar(&verifyMsgHex, "hex", false, "treat <message> as hex-encoded bytes")
	verifyMessageCmd.Flags().StringVar(&verifyAddress, "address", "", "expected signer address")
	rootCmd.AddCommand(verifyMessageCmd)
}

func runVerifyMessage(cmd *cobra.Command, args []string) error {
	if verifyMsgType != "personal" {
		return fmt.Errorf("unsupported --type %q", verifyMsgType)
	}

	msg, err := parseMessage(args[0], verifyMsgHex)
	if err != nil {
		return err
	}

	sig, err := hex.DecodeString(strings.TrimPrefix(args[1], "0x"))
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(sig) != 65 {
		return fmt.Errorf("invalid signature length: got %d bytes, want 65", len(sig))
	}

	addr, err := signer.RecoverPersonal(msg, sig)
	if err != nil {
		return fmt.Errorf("recover signer: %w", err)
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), addr.Hex()); err != nil {
		return err
	}

	if verifyAddress != "" {
		if !common.IsHexAddress(verifyAddress) {
			return fmt.Errorf("invalid expected address %q", verifyAddress)
		}
		expected := common.HexToAddress(verifyAddress)
		if !strings.EqualFold(addr.Hex(), expected.Hex()) {
			return fmt.Errorf("address mismatch: recovered %s, expected %s", addr.Hex(), expected.Hex())
		}
	}

	return nil
}
