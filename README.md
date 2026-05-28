# RustCryption

A lightweight encryption tool built with **WPF (.NET 8)** and a **Rust** backend, using the ChaCha20-Poly1305 authenticated encryption algorithm. Fully local and offline — no telemetry, no cloud, no accounts.

---

## Features

- **Encrypt entire folders** recursively or **single files** with one click
- **Decrypt** them back using the generated key
- Unique 256-bit key generated per encryption session
- ChaCha20-Poly1305 AEAD — authenticated encryption, tamper-evident
- In-memory encryption — encrypt raw bytes and get back a base64 blob
- Key generation independent of encryption — generate and store keys ahead of time
- Persistent history — every operation logged locally with its key and path
- Clean WPF UI with light/dark theme, persisted across sessions
- Rust backend compiled as a native DLL for performance

---

## How it works

The Rust backend walks the target folder recursively (or reads a single file) and encrypts every file in-place. Each file gets its own random 12-byte nonce, prepended to the ciphertext as `[nonce][ciphertext]`. A unique 256-bit key is generated per session and shown in the UI after encryption — paste it back in the Decrypt tab to reverse the process.

> ⚠️ The key is shown **once**. If you lose it, your files cannot be recovered.

---

## Stack

| Layer    | Technology                           |
|----------|--------------------------------------|
| UI       | C# / WPF / .NET 8                    |
| Backend  | Rust (compiled to `bazingaDlls.dll`) |
| Crypto   | `chacha20poly1305` crate             |
| FFI      | Rust `extern "C"` → C# `DllImport`  |

---

## Rust API

The backend exposes the following functions over FFI:

| Function | Description |
|---|---|
| `encrypt_folder(folder, key_out, buf_len)` | Encrypts a folder, returns generated key |
| `decrypt_folder(folder, key)` | Decrypts a folder with the given key |
| `encrypt_file(path, key)` | Encrypts a single file in-place |
| `decrypt_file(path, key)` | Decrypts a single file in-place |
| `generate_key(key_out, buf_len)` | Generates a standalone 256-bit key |

All functions return `0` on success and a non-zero error code on failure.

---

## Usage

### Encrypting a folder
Pick a folder → click **Encrypt** → copy the generated key and store it somewhere safe.

### Encrypting a single file
Click **File** in the path browser → select your file → click **Encrypt** → save the generated key.

### Decrypting
Pick the folder or file → paste the key → click **Decrypt**.

### Generating a standalone key
On the Encrypt page, click **Generate key** to produce a key independently of any encryption operation — useful if you want to pre-generate and store keys.

### History
Every encrypt, decrypt, and key generation operation is saved in the **History** tab with its path, key, algorithm, and timestamp. From there you can copy a key, send it straight to the Decrypt tab, or remove individual entries.

---

## Data layout

Every encrypted file follows this binary layout:

```
[ 12 bytes — nonce ][ N bytes — ChaCha20-Poly1305 ciphertext + 16-byte auth tag ]
```

The nonce is randomly generated per file. The 16-byte auth tag is appended by the AEAD cipher and verified on decryption — any tampering causes the file to be skipped rather than corrupted further.

---

## Important notes

- `.dll` files and `key.txt` inside the target folder are **skipped** to avoid breaking any running software
- Files that can't be read or written are silently skipped — the rest of the operation continues
- Decryption with a wrong key skips files it can't authenticate — it will not corrupt them further
- Encryption is **in-place** — back up anything critical before encrypting
- Settings (theme) and history are stored in `%AppData%\RustCryption\`

---

## Local storage

| File | Contents |
|---|---|
| `%AppData%\RustCryption\history.json` | Operation history with keys and paths |
| `%AppData%\RustCryption\settings.json` | UI preferences (theme) |