use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, AeadCore, KeyInit, OsRng}};
use base64::{Engine, engine::general_purpose::STANDARD};
use walkdir::WalkDir;
use std::ffi::CStr;
use std::os::raw::c_char;

const NONCE_SIZE: usize = 12;

// ── Key helpers ───────────────────────────────────────────────────────────────

pub fn generate_base64_key() -> String {
    STANDARD.encode(ChaCha20Poly1305::generate_key(&mut OsRng))
}

fn cipher_from_base64(base64_key: &str) -> Result<ChaCha20Poly1305, Box<dyn std::error::Error>> {
    let bytes = STANDARD.decode(base64_key)?;
    if bytes.len() != 32 {
        return Err("Key must be 32 bytes (256-bit)".into());
    }
    Ok(ChaCha20Poly1305::new(Key::from_slice(&bytes)))
}

// ── Folder encryption ─────────────────────────────────────────────────────────

/// Encrypts an entire folder, generates its own key, returns it as base64.
pub fn run_encryption_logic_without_key(folder: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key_raw = ChaCha20Poly1305::generate_key(&mut OsRng);
    let base64_key = STANDARD.encode(key_raw);
    let cipher = ChaCha20Poly1305::new(&key_raw);

    for entry in WalkDir::new(folder).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }

        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if entry.file_name() == "key.txt" || ext == "dll" { continue; }

        let plaintext = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = match cipher.encrypt(&nonce, plaintext.as_ref()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Layout: [12-byte nonce][ciphertext]
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        let _ = std::fs::write(path, blob);
    }

    Ok(base64_key)
}

/// Encrypts an entire folder using a provided base64 key.
pub fn run_encryption_with_key(folder: &str, base64_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = cipher_from_base64(base64_key)?;

    for entry in WalkDir::new(folder).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }

        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if entry.file_name() == "key.txt" || ext == "dll" { continue; }

        let plaintext = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = match cipher.encrypt(&nonce, plaintext.as_ref()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        let _ = std::fs::write(path, blob);
    }

    Ok(())
}

// ── Folder decryption ─────────────────────────────────────────────────────────

/// Decrypts an entire folder with the given base64 key.
pub fn run_decryption_logic(folder: &str, base64_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = cipher_from_base64(base64_key)?;

    for entry in WalkDir::new(folder).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }

        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if entry.file_name() == "key.txt" || ext == "dll" { continue; }

        let blob = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if blob.len() < NONCE_SIZE { continue; }

        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = match cipher.decrypt(nonce, ciphertext) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let _ = std::fs::write(path, plaintext);
    }

    Ok(())
}

// ── Single file operations ────────────────────────────────────────────────────

/// Encrypts a single file in-place with the given base64 key.
pub fn encrypt_single_file(path: &str, base64_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = cipher_from_base64(base64_key)?;

    let plaintext = std::fs::read(path)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).map_err(|e| e.to_string())?;

    // Layout: [12-byte nonce][ciphertext]
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ciphertext);
    std::fs::write(path, blob)?;

    Ok(())
}

/// Decrypts a single file in-place with the given base64 key.
pub fn decrypt_single_file(path: &str, base64_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = cipher_from_base64(base64_key)?;

    let blob = std::fs::read(path)?;
    if blob.len() < NONCE_SIZE {
        return Err("File too short to be a valid encrypted blob".into());
    }

    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed: wrong key or corrupted data")?;
    std::fs::write(path, plaintext)?;

    Ok(())
}

// ── In-memory operations ──────────────────────────────────────────────────────

/// Encrypts raw bytes with the given base64 key.
/// Returns a base64-encoded blob of [12-byte nonce][ciphertext].
pub fn encrypt_bytes_to_base64(data: &[u8], base64_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let cipher = cipher_from_base64(base64_key)?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| e.to_string())?;

    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(&blob))
}

/// Decrypts a base64-encoded [nonce][ciphertext] blob back to raw bytes.
pub fn decrypt_base64_to_bytes(base64_blob: &str, base64_key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = cipher_from_base64(base64_key)?;

    let blob = STANDARD.decode(base64_blob)?;
    if blob.len() < NONCE_SIZE {
        return Err("Blob too short to be valid".into());
    }

    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed: wrong key or corrupted data")?;
    Ok(plaintext)
}

// ── FFI exports ───────────────────────────────────────────────────────────────

/// Encrypts a folder and writes the generated key into key_out_buf.
/// C#: int encrypt_folder(string folder, StringBuilder keyBuf, int bufLen)
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

    let key = match run_encryption_logic_without_key(folder) {
        Ok(k) => k,
        Err(_) => return 3,
    };

    let key_bytes = key.as_bytes();
    if key_bytes.len() + 1 > buf_len as usize { return 4; }
    unsafe {
        std::ptr::copy_nonoverlapping(key_bytes.as_ptr() as *const c_char, key_out_buf, key_bytes.len());
        *key_out_buf.add(key_bytes.len()) = 0;
    }

    0
}

/// Decrypts a folder with the given key.
/// C#: int decrypt_folder(string folder, string base64Key)
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

/// Generates a base64 key and writes it into key_out_buf.
/// C#: int generate_key(StringBuilder keyBuf, int bufLen)
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

/// Encrypts a single file in-place.
/// C#: int encrypt_file(string path, string base64Key)
#[unsafe(no_mangle)]
pub extern "C" fn encrypt_file(
    path_ptr: *const c_char,
    key_ptr: *const c_char,
) -> i32 {
    if path_ptr.is_null() || key_ptr.is_null() { return 1; }

    let path = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return 2,
    };
    let key = match unsafe { CStr::from_ptr(key_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return 2,
    };

    match encrypt_single_file(path, key) {
        Ok(_) => 0,
        Err(_) => 3,
    }
}

/// Decrypts a single file in-place.
/// C#: int decrypt_file(string path, string base64Key)
#[unsafe(no_mangle)]
pub extern "C" fn decrypt_file(
    path_ptr: *const c_char,
    key_ptr: *const c_char,
) -> i32 {
    if path_ptr.is_null() || key_ptr.is_null() { return 1; }

    let path = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return 2,
    };
    let key = match unsafe { CStr::from_ptr(key_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return 2,
    };

    match decrypt_single_file(path, key) {
        Ok(_) => 0,
        Err(_) => 3,
    }
}