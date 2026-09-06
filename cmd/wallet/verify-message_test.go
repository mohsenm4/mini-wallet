package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func runVerifyMessageCmd(t *testing.T, args []string) (string, error) {
	t.Helper()
	buf := &bytes.Buffer{}
	verifyMessageCmd.SetOut(buf)
	verifyMessageCmd.SetErr(buf)
	err := runVerifyMessage(verifyMessageCmd, args)
	return strings.TrimSpace(buf.String()), err
}

func resetVerifyFlags() {
	verifyMsgType = "personal"
	verifyMsgHex = false
	verifyAddress = ""
}

func TestVerifyMessageCmd_UnsupportedType(t *testing.T) {
	resetVerifyFlags()
	verifyMsgType = "eip712"
	_, err := runVerifyMessageCmd(t, []string{"hello", "0x" + strings.Repeat("00", 65)})
	if err == nil {
		t.Fatal("expected error for unsupported --type, got nil")
	}
}

func TestVerifyMessageCmd_InvalidSigHex(t *testing.T) {
	resetVerifyFlags()
	_, err := runVerifyMessageCmd(t, []string{"hello", "0xzz"})
	if err == nil {
		t.Fatal("expected error for invalid signature hex, got nil")
	}
}

func TestVerifyMessageCmd_InvalidSigLength(t *testing.T) {
	resetVerifyFlags()
	_, err := runVerifyMessageCmd(t, []string{"hello", "0x1234"})
	if err == nil {
		t.Fatal("expected error for wrong signature length, got nil")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyHex := hex.EncodeToString(crypto.FromECDSA(priv))
	addr := crypto.PubkeyToAddress(priv.PublicKey).Hex()

	t.Setenv("WALLET_PRIVATE_KEY", keyHex)
	signMsgType = "personal"
	signMsgHex = false

	sig, err := runSignMessageCmd(t, []string{"hello"})
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	resetVerifyFlags()
	verifyAddress = addr
	out, err := runVerifyMessageCmd(t, []string{"hello", sig})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !strings.EqualFold(out, addr) {
		t.Fatalf("recovered address %q, want %q", out, addr)
	}
}

func TestVerifyMessageCmd_AddressMismatch(t *testing.T) {
	signerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	otherPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	t.Setenv("WALLET_PRIVATE_KEY", hex.EncodeToString(crypto.FromECDSA(signerPriv)))
	signMsgType = "personal"
	signMsgHex = false
	sig, err := runSignMessageCmd(t, []string{"hello"})
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	resetVerifyFlags()
	verifyAddress = crypto.PubkeyToAddress(otherPriv.PublicKey).Hex()
	if _, err := runVerifyMessageCmd(t, []string{"hello", sig}); err == nil {
		t.Fatal("expected address mismatch error, got nil")
	}
}
