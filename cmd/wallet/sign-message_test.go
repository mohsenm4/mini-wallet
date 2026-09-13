package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func newTestKeyHex(t *testing.T) string {
	t.Helper()
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return hex.EncodeToString(crypto.FromECDSA(priv))
}

func runSignMessageCmd(t *testing.T, args []string) (string, error) {
	t.Helper()
	buf := &bytes.Buffer{}
	signMessageCmd.SetOut(buf)
	signMessageCmd.SetErr(buf)
	err := runSignMessage(signMessageCmd, args)
	return strings.TrimSpace(buf.String()), err
}

func TestSignMessageCmd_MissingKey(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", "")
	signMsgType = "personal"
	signMsgHex = false
	if _, err := runSignMessageCmd(t, []string{"hello"}); err == nil {
		t.Fatal("expected error when WALLET_PRIVATE_KEY unset, got nil")
	}
}

func TestSignMessageCmd_UnsupportedType(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", newTestKeyHex(t))
	signMsgType = "eip712"
	signMsgHex = false
	if _, err := runSignMessageCmd(t, []string{"hello"}); err == nil {
		t.Fatal("expected error for unsupported --type, got nil")
	}
}

func TestSignMessageCmd_BadHexMessage(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", newTestKeyHex(t))
	signMsgType = "personal"
	signMsgHex = true
	if _, err := runSignMessageCmd(t, []string{"zzzz"}); err == nil {
		t.Fatal("expected error for bad hex message, got nil")
	}
}

func TestSignVerifyTypedRoundTrip(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	file := "../../internal/signer/testdata/mail.json"

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"sign-message", "--type=typed", file})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := strings.TrimSpace(out.String())

	out.Reset()
	rootCmd.SetArgs([]string{"verify-message", "--type=typed", file, sig,
		"--address", "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignTyped_MissingFile(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	rootCmd.SetArgs([]string{"sign-message", "--type=typed", "does-not-exist.json"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "read typed data file") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestSignMessageCmd_OutputShape(t *testing.T) {
	t.Setenv("WALLET_PRIVATE_KEY", newTestKeyHex(t))
	signMsgType = "personal"
	signMsgHex = false

	out, err := runSignMessageCmd(t, []string{"hello"})
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if !strings.HasPrefix(out, "0x") {
		t.Fatalf("expected 0x-prefixed signature, got %q", out)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(out, "0x"))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(raw) != 65 {
		t.Fatalf("expected 65-byte signature, got %d", len(raw))
	}
	if v := raw[64]; v != 27 && v != 28 {
		t.Fatalf("expected recovery id 27 or 28, got %d", v)
	}
}
