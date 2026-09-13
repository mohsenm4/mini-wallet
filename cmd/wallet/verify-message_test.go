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

func TestSignVerifyTypedRoundTrip(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	file := "../../internal/signer/testdata/mail.json"

	signMsgType, signMsgHex = "typed", false
	sig, err := runSignMessageCmd(t, []string{file})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifyMsgType, verifyMsgHex = "typed", false
	verifyAddress = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
	if _, err := runVerifyMessageCmd(t, []string{file, sig}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignMessageCmd_TypedMissingFile(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", newTestKeyHex(t))
	signMsgType, signMsgHex = "typed", false
	_, err := runSignMessageCmd(t, []string{"does-not-exist.json"})
	if err == nil || !strings.Contains(err.Error(), "read typed data file") {
		t.Fatalf("expected read error, got %v", err)
	}
}
