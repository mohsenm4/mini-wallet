# BIP32 — Hardened vs Non-hardened Child Derivation

> Notes from studying BIP32 for `mini-wallet`. Written after implementing
> `NewMasterKey` and non-hardened `Child()` — before adding hardened support.

---

## 1. Where we are in the pipeline

```
mnemonic (BIP39)
   │  PBKDF2-HMAC-SHA512, 2048 rounds, salt = "mnemonic" + passphrase
   ▼
seed (64 bytes)
   │  HMAC-SHA512(key = "Bitcoin seed", data = seed)
   ▼
master key   =  Key (32 bytes)  +  ChainCode (32 bytes)
   │  Child(i) — this document
   ▼
child key    =  Key' (32 bytes) +  ChainCode' (32 bytes)
```

Every child is itself a full key that can produce grandchildren. This is
what "hierarchical deterministic" (HD) means.

**Analogy**: the master key is a golden key to the "root vault". The chain
code is a family seal that acts as extra secret entropy when producing
child keys. Without the seal, even someone who steals a child key can't
walk backward to the parent.

---

## 2. Why child keys exist at all

Using one address for every transaction destroys privacy — anyone reading
the chain can link all of your activity. HD wallets solve this: from one
`mnemonic`, deterministically derive an unlimited number of child keys,
and use a fresh one per transaction. Backup remains one thing (the
mnemonic).

---

## 3. Two modes of `Child(i)`

The BIP32 spec defines the child index space as `[0, 2^32)`, split in half:

| Index range          | Mode          | HMAC input                                |
|----------------------|---------------|-------------------------------------------|
| `i <  2^31`          | Non-hardened  | `serP(K_parent) \|\| ser32(i)`            |
| `i >= 2^31`          | Hardened      | `0x00 \|\| k_parent \|\| ser32(i)`        |

Where:
- `serP(K)` = compressed public key of `K`, 33 bytes (`0x02` or `0x03` prefix + x-coord)
- `k_parent` = raw private key of parent, 32 bytes
- `ser32(i)` = index as 4-byte big-endian

Everything else in the algorithm — HMAC-SHA512 with chain code as key,
split into IL/IR, tweak `child_key = (parent_key + IL) mod n`, IR becomes
new chain code — is **identical**.

**The only thing that changes is what goes into the HMAC.**

---

## 4. Why we care — the attack that motivates hardening

An **xpub** ("extended public key") is `(K_parent, ChainCode_parent)`. It
is the artifact you give to a watch-only wallet, an accountant, or a
block explorer so they can *see* balances without being able to *spend*.
Public info, safe to share — or is it?

### Attack: leaked non-hardened child + xpub → parent private key

Suppose:
- You gave someone your `xpub` (the parent's public key + chain code).
- Somewhere down the line, **one** non-hardened child's private key
  (`child_key`) leaks — maybe from a hot wallet on a compromised
  machine.

The attacker can now recover the parent's private key with basic
arithmetic:

```
Given (from the leaked child):     child_key
Given (from xpub):                  K_parent, ChainCode_parent

Recompute IL from public inputs:
    data = serP(K_parent) || ser32(i)          ← same inputs the child derivation used
    I    = HMAC-SHA512(ChainCode_parent, data)
    IL   = I[:32]

Invert the tweak:
    parent_key = (child_key - IL) mod n         ← done. Parent private key recovered.
```

Because the HMAC input for **non-hardened** children uses only *public*
material (`serP(K_parent)`), the attacker can reproduce `IL` from the
xpub they already have. Combining `IL` with the leaked child key inverts
the derivation.

**Catastrophic consequence**: recovering `parent_key` gives the attacker
every sibling and every descendant of the parent — the entire subtree.

### How hardening blocks it

For a hardened child, the HMAC input is `0x00 || k_parent || ser32(i)`.
Now `IL` depends on the *private* key of the parent. The attacker holding
only `xpub` cannot compute `IL`, so the inversion is impossible.

Hardened derivation trades off the ability to derive child *public* keys
from `xpub` (breaking watch-only for that subtree) in exchange for
containing damage: a leak below a hardened boundary cannot climb above
it.

---

## 5. Why the prefix is `0x00`

Compare the two HMAC inputs:

```
Non-hardened:  serP(K_parent)  || ser32(i)     →  33 + 4 = 37 bytes
Hardened:      0x00 || k_parent || ser32(i)     →   1 + 32 + 4 = 37 bytes
```

Two reasons the prefix is `0x00`:

1. **Same length (37 bytes)** — keeps the HMAC call uniform, code stays
   simple.

2. **Domain separation** — a compressed public key *always* starts with
   `0x02` or `0x03` (the byte encodes the parity of the y coordinate).
   By choosing `0x00`, the hardened input is guaranteed never to collide
   with any non-hardened input, even by accident. Non-hardened outputs
   and hardened outputs live in disjoint universes.

Any byte value outside `{0x02, 0x03}` would satisfy reason 2. `0x00` is
the natural choice.

---

## 6. Algorithm diff (Go, roughly)

```go
// Non-hardened branch (already implemented):
serP := crypto.CompressPubkey(&pvk.PublicKey) // 33 bytes
data := make([]byte, 37)
copy(data[:33], serP)
binary.BigEndian.PutUint32(data[33:], i)

// Hardened branch (what we're about to add):
data := make([]byte, 37)
data[0] = 0x00
copy(data[1:33], k.Key[:])                    // 32 bytes of parent private key
binary.BigEndian.PutUint32(data[33:], i)

// Everything after this line is identical for both branches:
h := hmac.New(sha512.New, k.ChainCode[:])
h.Write(data)
sum := h.Sum(nil)
il := new(big.Int).SetBytes(sum[:32])
ir := sum[32:]
if il.Cmp(curveN) >= 0 { return nil, errors.New("IL >= n") }
childKey := new(big.Int).Add(il, pvk.D)
childKey.Mod(childKey, curveN)
if childKey.Sign() == 0 { return nil, errors.New("derived key is zero") }
```

---

## 7. Property comparison

| Property                                          | Non-hardened | Hardened |
|---------------------------------------------------|--------------|----------|
| Index range                                       | `[0, 2^31)` | `[2^31, 2^32)` |
| HMAC input material                               | Public key   | Private key |
| Can derive child xpub from parent xpub?           | ✅ Yes       | ❌ No |
| Watch-only wallet works for this subtree?         | ✅ Yes       | ❌ No |
| Leak of one child privkey + xpub → parent privkey? | 🔴 **YES — catastrophic** | 🟢 No |
| Contains a compromise below this level?           | ❌ No        | ✅ Yes |

---

## 8. Rule of thumb (where BIP44 uses each)

`m / 44' / 60' / 0' / 0 / N`

| Level  | Reason it's hardened / not                                    |
|--------|--------------------------------------------------------------|
| `44'`  | Hardened. Isolates the "purpose" so a leak in one BIP standard's subtree can't compromise siblings from other standards. |
| `60'`  | Hardened. Isolates coins. A leak in Ethereum shouldn't touch Bitcoin. |
| `0'`   | Hardened. Isolates accounts. Sharing an account's xpub with an accountant must not expose other accounts. |
| `0`    | Non-hardened. This is the "external chain" (receive addresses). We *want* watch-only wallets to work here. |
| `N`    | Non-hardened. This is the address index. Same reason — watch-only support. |

**Pattern**: hardened boundaries protect *what should stay isolated*.
Non-hardened boundaries enable *what should be observable*.

---

## 9. References

- BIP32 spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- BIP44 spec: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
- SLIP-44 coin types: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
