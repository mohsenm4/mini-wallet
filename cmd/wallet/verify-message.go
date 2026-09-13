package main

import (
	"encoding/hex"
	"fmt"
	"os"
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
	sig, err := hex.DecodeString(strings.TrimPrefix(args[1], "0x"))
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(sig) != 65 {
		return fmt.Errorf("invalid signature length: got %d bytes, want 65", len(sig))
	}

	var addr common.Address
	switch verifyMsgType {
	case "personal":
		msg, err := parseMessage(args[0], verifyMsgHex)
		if err != nil {
			return err
		}
		if addr, err = signer.RecoverPersonal(msg, sig); err != nil {
			return fmt.Errorf("recover signer: %w", err)
		}
	case "typed":
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read typed data file: %w", err)
		}
		td, err := signer.ParseTypedDataJSON(raw)
		if err != nil {
			return fmt.Errorf("parse typed data: %w", err)
		}
		if addr, err = signer.RecoverTyped(td, sig); err != nil {
			return fmt.Errorf("recover typed signer: %w", err)
		}
	default:
		return fmt.Errorf("unsupported --type %q", verifyMsgType)
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
