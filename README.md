# 1Password → Apple Passwords

Migrate your 1Password vault to Apple Passwords. Supports **all item types** — logins, credit cards, bank accounts, secure notes, identities, crypto wallets, and more.

## 🌐 Web Version (Recommended)

Open `index.html` in your browser. Everything runs locally — **no data is sent anywhere**.

1. Export from 1Password: **File → Export → 1PUX format**
2. Drop the `.1pux` file onto the page
3. Download the CSV
4. Import into Apple Passwords: **File → Import Passwords…**

## 🐍 CLI Version

```bash
python3 migrate.py ~/Downloads/export.1pux
```

Options:
- `--output`, `-o` — Output CSV path (default: `passwords.csv`)
- `--report`, `-r` — Skipped items report (default: `skipped_items.txt`)

## What migrates

| Category | How it's stored |
|----------|----------------|
| Logins & Passwords | Username, password, URL, TOTP |
| Credit Cards | All fields in Notes |
| Bank Accounts | All fields in Notes |
| Identities | All fields in Notes |
| Secure Notes | Note content in Notes |
| Crypto Wallets | All fields in Notes |
| Software Licenses | All fields in Notes |
| Everything else | All fields in Notes |

- **Archived items** are migrated with `[Archived]` tag in Notes
- **Trashed items** are the only ones skipped
- **TOTP/2FA codes** are preserved in the OTPAuth column

## Privacy

Both the web and CLI versions run 100% locally. No network requests, no telemetry, no data collection.

## License

MIT
