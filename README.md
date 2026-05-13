# BazingaVault

A lightweight folder encryption tool built with **WPF (.NET 8)** and a **Rust** backend, using the ChaCha20-Poly1305 authenticated encryption algorithm. Fully local and offline — no telemetry, no cloud, no accounts.

---

## Features

- **Encrypt entire folders** recursively with a single click
- **Decrypt** them back using the generated key
- Unique 256-bit key generated per encryption session
- ChaCha20-Poly1305 AEAD — authenticated encryption, tamper-evident
- Clean WPF UI with light/dark theme
- Rust backend compiled as a native DLL for performance

---

## How it works

The Rust backend walks the folder recursively and encrypts every file in-place. Each file gets its own random nonce, stored as `[12-byte nonce][ciphertext]`. A unique 256-bit key is generated per session and shown in the UI after encryption — paste it back in the Decrypt tab to reverse the process.

> ⚠️ The key is shown **once**. If you lose it, your files cannot be recovered.

---

## Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| UI       | C# / WPF / .NET 8                   |
| Backend  | Rust (compiled to `bazingaDlls.dll`)|
| Crypto   | `chacha20poly1305` crate            |
| FFI      | Rust `extern "C"` → C# `DllImport` |

---


## Usage

### Encrypting
Pick a folder → click **Encrypt folder** → copy the generated key and store it somewhere safe.

### Decrypting
Pick the same folder → paste the key → click **Decrypt folder**.

---

## Important notes

- `.dll` files inside the target folder are **skipped** to avoid breaking any running software
- Files that can't be read or written are silently skipped — no crash
- Decryption with a wrong key skips files it can't authenticate — it won't corrupt them further
- The tool encrypts **in-place** — back up anything critical before encrypting