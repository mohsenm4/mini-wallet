# Mnemonic Storage — Decision

## Context
وقتی `wallet new` mnemonic تولید می‌کنه، الان فقط print می‌شه. کاربر
اگه اشتباه پنجره رو ببنده، mnemonic رفته. باید یه راه ذخیره باشه که
هم امن باشه هم UX خوبی داشته باشه.

## Options
### A — save نکن (وضعیت فعلی)
- Pro: هیچ فایل حساسی روی دیسک نمی‌ره
- Con: UX ضعیف، user error پرهزینه

### B — plaintext توی ~/.config/mini-wallet/
- Pro: ساده
- Con: هر پروسه‌ی دیگه با access filesystem = دسترسی کامل

### C — encrypted keystore V3 style توی ./data/
- Pro: امن (scrypt + AES-CTR + MAC)، کد keystore V3 reuse می‌شه
- Con: کاربر باید password یادش بمونه، `data/` باید توی .gitignore باشه

## Decision
**C** — encrypted keystore V3 style، entropy bytes رمز می‌شه (نه mnemonic string)، فایل `data/wallet.json`.

## Consequences
- `data/` توی `.gitignore` (ریسک commit اشتباهی)
- `internal/keystore.Encrypt` باید signature عوض کنه از `[32]byte` به `[]byte`
- موقع load، از entropy → `mnemonic.FromEntropy` → mnemonic بازسازی می‌شه
- Password هم برای `export-keystore` هم `wallet new --save` = یکسان (env `WALLET_PASSWORD` fallback به prompt)
