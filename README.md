# mini-wallet

Ethereum HD wallet CLI written in Go. Implements BIP39 (mnemonic),
BIP32 (HD derivation), BIP44 (path structure), ECDSA sign/verify on
secp256k1, and Web3 Secret Storage (keystore V3) import/export.

Built for learning — not audited, not for production key management.

## Features

- Generate BIP39 mnemonic (128 / 160 / 192 / 224 / 256 bits)
- Derive Ethereum addresses at any BIP32 path (default `m/44'/60'/0'/0/N`)
- Sign a 32-byte hash and recover the signing address
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

### Derive an address

```sh
$ export WALLET_MNEMONIC="much mesh access uncle easily arrange thank scorpion scatter grape paper found"
$ wallet derive --index=0
Path:        m/44'/60'/0'/0/0
Address:     0xA9285Fdb26a1E01057Da968A909624DF058D70E8
PrivateKey:  0x24ba9fa447530cbeb2f0eea8d132c8692183c491bf5138640e2e48e4c2033f3a
```

Use `--path` to derive at an arbitrary BIP32 path instead of `--index`.

### Sign and verify

```sh
$ export WALLET_PRIVATE_KEY="0x24ba9fa447530cbeb2f0eea8d132c8692183c491bf5138640e2e48e4c2033f3a"
$ wallet sign 0x0000000000000000000000000000000000000000000000000000000000000000
Signature:   0x...

$ wallet verify --hash=0x00...00 --signature=0x...
Recovered:   0xA9285Fdb26a1E01057Da968A909624DF058D70E8
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
  new, derive, sign, verify, export-keystore, import-keystore

internal/
  mnemonic/                BIP39 — entropy, wordlist, checksum, seed
  hd/                      BIP32 + BIP44 — master key, child key, path parser
  keys/                    Ethereum address from public key (Keccak256 last 20 bytes)
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

| Variable             | Used by                              | Purpose                           |
|----------------------|--------------------------------------|-----------------------------------|
| `WALLET_MNEMONIC`    | `derive`, `export-keystore`          | The BIP39 phrase                  |
| `WALLET_PASSPHRASE`  | `derive`, `export-keystore`          | Optional BIP39 passphrase         |
| `WALLET_PRIVATE_KEY` | `sign`                               | 32-byte hex private key           |
| `WALLET_PASSWORD`    | `export-keystore`, `import-keystore` | Non-interactive keystore password |

If `WALLET_PASSWORD` is unset, the CLI prompts on the terminal.

## Testing

```sh
go test ./... -cover
```

Reference vectors from the Ethereum Web3 Secret Storage spec are included
in [internal/keystore/keystore_test.go](internal/keystore/keystore_test.go).

## Design notes

- [docs/design/mnemonic-storage.md](docs/design/mnemonic-storage.md) — encrypted persistence of BIP39 entropy

## License

MIT
