//! `SEKEY001` key file: magic, 32 random bytes, SHA-256 of the first 40 bytes.

use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"SEKEY001";
const SECRET_END: usize = 40;
pub const FILE_LEN: usize = SECRET_END + 32;

/// Prefix of the QR transfer text. Uppercase hexadecimal keeps the whole
/// text in the compact alphanumeric mode of QR codes.
pub const TRANSFER_PREFIX: &str = "SEKEEPER-KEY:1:";

#[derive(Debug, Error)]
pub enum KeyFileError {
    #[error("file chiave non valido o danneggiato: seleziona il file generato da Sekeeper")]
    Invalid,
    #[error("questo QR code non contiene un file chiave di Sekeeper")]
    InvalidTransfer,
    #[error("generatore casuale del sistema non disponibile")]
    Random,
}

// The secret is never serialized into the vault, configuration or S3 objects.
// This type deliberately has no Debug or Serialize implementation.
pub struct KeyFile(Zeroizing<[u8; 32]>);

impl KeyFile {
    /// Content of a new key file, ready to be written by the caller.
    pub fn new_file() -> Result<Zeroizing<[u8; FILE_LEN]>, KeyFileError> {
        let mut bytes = Zeroizing::new([0u8; FILE_LEN]);
        bytes[..8].copy_from_slice(MAGIC);
        OsRng
            .try_fill_bytes(&mut bytes[8..SECRET_END])
            .map_err(|_| KeyFileError::Random)?;
        let checksum = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&bytes[..SECRET_END])));
        bytes[SECRET_END..].copy_from_slice(checksum.as_slice());
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, KeyFileError> {
        if bytes.len() != FILE_LEN {
            return Err(KeyFileError::Invalid);
        }
        let checksum = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&bytes[..SECRET_END])));
        if &bytes[..8] != MAGIC || bytes[SECRET_END..] != *checksum {
            return Err(KeyFileError::Invalid);
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&bytes[8..SECRET_END]);
        Ok(Self(secret))
    }

    /// Text for a QR code carrying the whole key file, checksum included.
    pub fn transfer_text(file: &[u8]) -> Result<Zeroizing<String>, KeyFileError> {
        Self::parse(file)?;
        let mut text = Zeroizing::new(String::with_capacity(TRANSFER_PREFIX.len() + FILE_LEN * 2));
        text.push_str(TRANSFER_PREFIX);
        for byte in file {
            text.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
            text.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 15)]));
        }
        Ok(text)
    }

    /// The key file carried by a QR transfer text, verified like a file.
    pub fn from_transfer_text(text: &str) -> Result<Zeroizing<[u8; FILE_LEN]>, KeyFileError> {
        let hex = text
            .trim()
            .strip_prefix(TRANSFER_PREFIX)
            .filter(|hex| hex.len() == FILE_LEN * 2)
            .ok_or(KeyFileError::InvalidTransfer)?;
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        let mut file = Zeroizing::new([0u8; FILE_LEN]);
        for (index, [high, low]) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let (Some(high), Some(low)) = (digit(*high), digit(*low)) else {
                return Err(KeyFileError::InvalidTransfer);
            };
            file[index] = high << 4 | low;
        }
        Self::parse(file.as_slice())?;
        Ok(file)
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// Public test value, never used by production creation or unlock paths.
    #[cfg(any(test, feature = "testing"))]
    pub fn test_key() -> Self {
        Self(Zeroizing::new([0x42; 32]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_files_parse_and_any_damage_is_rejected() {
        let first = KeyFile::new_file().unwrap();
        let second = KeyFile::new_file().unwrap();
        assert_ne!(*first, *second);
        let key = KeyFile::parse(first.as_slice()).unwrap();
        assert_eq!(key.secret().as_slice(), &first[8..SECRET_END]);
        for offset in [0, 8, 39, 40, 71] {
            let mut bytes = *first;
            bytes[offset] ^= 1;
            assert!(KeyFile::parse(&bytes).is_err());
        }
        for length in [0, 32, FILE_LEN - 1, FILE_LEN + 1] {
            assert!(KeyFile::parse(&vec![0; length]).is_err());
        }
    }

    #[test]
    fn transfer_text_roundtrips_and_rejects_anything_else() {
        let file = KeyFile::new_file().unwrap();
        let text = KeyFile::transfer_text(file.as_slice()).unwrap();
        assert!(text.starts_with(TRANSFER_PREFIX));
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase() || b":-".contains(&b))
        );
        assert_eq!(*KeyFile::from_transfer_text(&text).unwrap(), *file);
        assert!(KeyFile::transfer_text(&file[..71]).is_err());
        let mut damaged = text.to_string();
        damaged.replace_range(30..31, if &damaged[30..31] == "0" { "1" } else { "0" });
        assert!(KeyFile::from_transfer_text(&damaged).is_err());
        for invalid in [
            "",
            "https://example.org",
            &text[..text.len() - 2],
            &text.to_lowercase(),
        ] {
            assert!(KeyFile::from_transfer_text(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn the_public_fixture_is_the_documented_test_key() {
        let fixture = include_bytes!("../tests/fixtures/public-test.key");
        let key = KeyFile::parse(fixture).unwrap();
        assert_eq!(key.secret(), KeyFile::test_key().secret());
    }
}
