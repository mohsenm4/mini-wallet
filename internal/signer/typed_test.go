package signer

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func mailExample() TypedData {
	return TypedData{
		Types: map[string][]Field{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Person": {
				{Name: "name", Type: "string"},
				{Name: "wallet", Type: "address"},
			},
			"Mail": {
				{Name: "from", Type: "Person"},
				{Name: "to", Type: "Person"},
				{Name: "contents", Type: "string"},
			},
		},
		PrimaryType: "Mail",
		Domain: TypedDataDomain{
			Name:              "Ether Mail",
			Version:           "1",
			ChainID:           big.NewInt(1),
			VerifyingContract: common.HexToAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
		},
		Message: map[string]any{
			"from": map[string]any{
				"name":   "Cow",
				"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
			},
			"to": map[string]any{
				"name":   "Bob",
				"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
			},
			"contents": "Hello, Bob!",
		},
	}
}

func TestEncodeType_MailExample(t *testing.T) {
	td := mailExample()

	got := EncodeType(td.PrimaryType, td.Types)

	want := "Mail(Person from,Person to,string contents)Person(string name,address wallet)"

	if got != want {
		t.Fatalf("EncodeType() = %q, want %q", got, want)
	}
}

func TestHashStruct_Mail(t *testing.T) {
	td := mailExample()

	got, err := HashStruct(td.PrimaryType, td.Message, td.Types)
	if err != nil {
		t.Fatal(err)
	}

	want := "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"

	if common.Bytes2Hex(got) != want {
		t.Fatalf("HashStruct() = 0x%s, want 0x%s", common.Bytes2Hex(got), want)
	}
}

func TestHashDomain_Mail(t *testing.T) {
	td := mailExample()

	got, err := HashDomain(td.Domain)
	if err != nil {
		t.Fatal(err)
	}

	want := "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"

	if common.Bytes2Hex(got) != want {
		t.Fatalf("HashDomain() = 0x%s, want 0x%s", common.Bytes2Hex(got), want)
	}
}

func TestSignRecoverTyped_RoundTrip(t *testing.T) {
	td := mailExample()

	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := SignTyped(priv, td)
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := RecoverTyped(td, sig)
	if err != nil {
		t.Fatal(err)
	}

	expected := crypto.PubkeyToAddress(priv.PublicKey)

	if recovered != expected {
		t.Fatalf("address mismatch: got %s, want %s", recovered.Hex(), expected.Hex())
	}
}
