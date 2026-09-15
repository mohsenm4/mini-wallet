# mini-wallet

Ethereum HD wallet CLI written in Go. Implements BIP39 (mnemonic),
BIP32 (HD derivation), BIP44 (path structure), ECDSA sign/verify on
secp256k1, EIP-191 / EIP-712 message signing, and Web3 Secret Storage
(keystore V3) import/export.

Built for learning — not audited, not for production key management.

## Features

- Generate BIP39 mnemonic (128 / 160 / 192 / 224 / 256 bits)
- Save the wallet encrypted on disk and load it back
- Derive Ethereum addresses at any BIP32 path (default `m/44'/60'/0'/0/N`)
- Sign a 32-byte hash and recover the signing address
- Sign and verify human-readable messages (EIP-191 `personal_sign`)
- Sign and verify typed data (EIP-712 `eth_signTypedData_v4`) from a JSON file
- Export a derived key as an encrypted keystore V3 JSON
- Import a keystore V3 JSON and print the address

## Install

```sh
go install github.com/mohsenm4/mini-wallet/cmd/wallet@latest
```

Or build from source:

```sh
go build -o wallet ./cmd/wallet
```

## Usage

### Generate a mnemonic

```sh
$ wallet new --bits=128
Generated mnemonic: much mesh access uncle easily arrange thank scorpion scatter grape paper found
```

### Save and load a wallet

```sh
$ export WALLET_PASSWORD="strong-password"
$ wallet new --save --out=data/wallet.json
Generated mnemonic: much mesh access uncle easily arrange thank scorpion scatter grape paper found
Saved to: data/wallet.json

$ wallet load --in=data/wallet.json
Address: 0xA9285Fdb26a1E01057Da968A909624DF058D70E8
```

Only the BIP39 entropy is stored, encrypted with the password. Pass
`--show-mnemonic` to `load` to print the phrase, and `--force` to
`new --save` to overwrite an existing file.

### Derive an address

```sh
$ export WALLET_MNEMONIC="much mesh access uncle easily arrange thank scorpion scatter grape paper found"
$ wallet derive --index=0
Path:        m/44'/60'/0'/0/0
Address:     0xA9285Fdb26a1E01057Da968A909624DF058D70E8
PrivateKey:  0x24ba9fa447530cbeb2f0eea8d132c8692183c491bf5138640e2e48e4c2033f3a
```

Use `--path` to derive at an arbitrary BIP32 path instead of `--index`.

### Sign and verify a raw hash

```sh
$ export WALLET_PRIVATE_KEY="0x24ba9fa447530cbeb2f0eea8d132c8692183c491bf5138640e2e48e4c2033f3a"
$ wallet sign 0x0000000000000000000000000000000000000000000000000000000000000000
0x12608febbc823d9a7d5c96594d963b2f61c565b42ba7e3ecc20cba3db42bd877060094fc833ab2e4261ceff3b304a673f0806dadc636634c2981769a1d04253100

$ wallet verify 0x12608febbc823d9a7d5c96594d963b2f61c565b42ba7e3ecc20cba3db42bd877060094fc833ab2e4261ceff3b304a673f0806dadc636634c2981769a1d04253100 0x0000000000000000000000000000000000000000000000000000000000000000
Recovered address: 0xA9285Fdb26a1E01057Da968A909624DF058D70E8
```

### Sign and verify a message

`sign` works on a raw 32-byte hash. Real wallets sign *messages*, with a
prefix that stops a signature from being reused as a transaction.

EIP-191 `personal_sign`:

```sh
$ export WALLET_PRIVATE_KEY="0x24ba9fa447530cbeb2f0eea8d132c8692183c491bf5138640e2e48e4c2033f3a"
$ wallet sign-message "hello world"
0x629682434c0691585155220909bd4abbd4607eb1b8d7624bec344712715995fa5f85482b26f4252a7fad897b9f0056402bc65273fdd9beb5941c845208310ca61b

$ wallet verify-message "hello world" 0x629682434c0691585155220909bd4abbd4607eb1b8d7624bec344712715995fa5f85482b26f4252a7fad897b9f0056402bc65273fdd9beb5941c845208310ca61b --address=0xA9285Fdb26a1E01057Da968A909624DF058D70E8
0xA9285Fdb26a1E01057Da968A909624DF058D70E8
```

Pass `--hex` to treat the message as hex-encoded bytes. `--address` is
optional; when given, the command fails if the recovered signer differs.

EIP-712 typed data (`eth_signTypedData_v4` JSON, the same format MetaMask uses):

```sh
$ wallet sign-message --type=typed internal/signer/testdata/mail.json
0x1b130aafc85056a9e7558468f5b53e287d0b7a65a2c8ebd2163622b5c7a20c3e7096f78ba26d7c3b44ff315f32192bcda5f8b45e1f4f2b7624d92a2ee90f1a321b

$ wallet verify-message --type=typed internal/signer/testdata/mail.json 0x1b130aafc85056a9e7558468f5b53e287d0b7a65a2c8ebd2163622b5c7a20c3e7096f78ba26d7c3b44ff315f32192bcda5f8b45e1f4f2b7624d92a2ee90f1a321b
0xA9285Fdb26a1E01057Da968A909624DF058D70E8
```

### Export / import keystore

```sh
$ export WALLET_PASSWORD="strong-password"
$ wallet export-keystore --index=0 --out=account.json
Keystore exported to account.json

$ wallet import-keystore account.json
Address:     0xA9285Fdb26a1E01057Da968A909624DF058D70E8
```

Pass `--show-private` to also print the decrypted private key.

## Architecture

```text
cmd/wallet/                CLI entry point (Cobra commands)
  new, load, derive, sign, verify, sign-message, verify-message,
  export-keystore, import-keystore

internal/
  mnemonic/                BIP39 — entropy, wordlist, checksum, seed
  hd/                      BIP32 + BIP44 — master key, child key, path parser
  keys/                    Ethereum address from public key (Keccak256 last 20 bytes)
  signer/                  EIP-191 personal_sign + EIP-712 typed data (hashStruct, domain separator)
  keystore/                Web3 Secret Storage V3 — scrypt + AES-128-CTR + Keccak256 MAC
```

Flow for `derive`:

```text
mnemonic ──PBKDF2──▶ seed ──HMAC-SHA512──▶ master (key, chainCode)
                                              │
                                              ▼ Child(i) for each path segment
                                          derived key
                                              │
                                              ▼ crypto.ToECDSA + PubkeyToAddress
                                          0xADDRESS
```

## Environment variables

| Variable             | Used by                                                    | Purpose                                         |
|----------------------|------------------------------------------------------------|-------------------------------------------------|
| `WALLET_MNEMONIC`    | `derive`, `export-keystore`                                | The BIP39 phrase                                |
| `WALLET_PASSPHRASE`  | `derive`, `export-keystore`                                | Optional BIP39 passphrase                       |
| `WALLET_PRIVATE_KEY` | `sign`, `sign-message`                                     | 32-byte hex private key                         |
| `WALLET_PASSWORD`    | `new --save`, `load`, `export-keystore`, `import-keystore` | Non-interactive keystore / wallet-file password |

If `WALLET_PASSWORD` is unset, the CLI prompts on the terminal.

## Testing

```sh
go test ./... -cover
```

Reference vectors from the Ethereum Web3 Secret Storage spec are included
in [internal/keystore/keystore_test.go](internal/keystore/keystore_test.go).

## Design notes

- [docs/design/mnemonic-storage.md](docs/design/mnemonic-storage.md) — encrypted persistence of BIP39 entropy
- [Ethereum cryptography from a Go dev's view](https://dev.to/mohsenm4/ethereum-cryptography-from-a-go-devs-view-47h8) — blog post: BIP39/32/44, keystore V3, EIP-191/712, and three bugs the tests caught

## License

MIT
