package signer

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestParseTypedDataJSON(t *testing.T) {
	data, err := os.ReadFile("testdata/mail.json")
	if err != nil {
		t.Fatal(err)
	}

	td, err := ParseTypedDataJSON(data)
	if err != nil {
		t.Errorf("ParseTypedDataJSON failed: %v", err)
		return
	}

	got, err := HashStruct(td.PrimaryType, td.Message, td.Types)
	if err != nil {
		t.Errorf("HashStruct failed: %v", err)
		return
	}
	want := "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
	if hex.EncodeToString(got) != want {
		t.Fatalf("HashStruct = %x, want %s", got, want)
	}
}

func TestParseTypedDataJSON_Uint256(t *testing.T) {
	data := []byte(`{
	  "types": {"Transfer": [{"name":"amount","type":"uint256"}]},
	  "primaryType": "Transfer",
	  "domain": {"name":"T","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
	  "message": {"amount": 115792089237316195423570985008687907853269984665640564039457584007913129639935}
	}`)
	td, err := ParseTypedDataJSON(data)
	if err != nil {
		t.Fatal(err)
	}

	typeHash := crypto.Keccak256([]byte("Transfer(uint256 amount)"))
	maxU256 := bytes.Repeat([]byte{0xff}, 32)
	want := crypto.Keccak256(append(typeHash, maxU256...))

	got, err := HashStruct(td.PrimaryType, td.Message, td.Types)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}

}
