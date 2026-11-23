//! `SEKEEPER` v3: a 52-byte header, authenticated in full as AES-GCM AAD,
//! followed by the encrypted JSON of [`VaultData`]. The key comes from
//! Argon2id over the master password, with the key file as secret input K.

use crate::i18n::tr;
use crate::keyfile::KeyFile;
use crate::limits::{self, MAX_LINEAGE, MAX_PARENTS, MAX_SNAPSHOT_BYTES};
use crate::model::{Revision, RevisionLink, VaultData};
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use rand::RngCore;
use std::fmt;
use std::sync::Mutex;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"SEKEEPER";
pub const VERSION: u8 = 3;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const SALT_START: usize = 24;
pub const NONCE_START: usize = SALT_START + SALT_LEN;
pub const HEADER_LEN: usize = NONCE_START + NONCE_LEN;
pub const TAG_LEN: usize = 16;
pub const MEMORY_KIB: u32 = 256 * 1024;
pub const ITERATIONS: u32 = 3;
pub const PARALLELISM: u32 = 4;

/// One derivation at a time: each needs 256 MiB, and parallel callers such as
/// test runners or a phone under memory pressure must not multiply that.
pub static KDF_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, PartialEq, Eq)]
pub enum FormatError {
    InvalidPasswordOrCorrupted,
    InvalidFormat,
    KeyDerivation,
    Encryption,
    InvalidData,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPasswordOrCorrupted => tr(
                "wrong password or key file, or corrupted vault",
                "password o file chiave errati, oppure vault danneggiato",
            ),
            Self::InvalidFormat => tr(
                "invalid or unsupported vault format: a v3 vault with a key file is required",
                "formato del vault non valido o non supportato: serve un vault v3 con file chiave",
            ),
            Self::KeyDerivation => tr(
                "error deriving the key",
                "errore durante la derivazione della chiave",
            ),
            Self::Encryption => tr(
                "error encrypting the vault",
                "errore durante la cifratura del vault",
            ),
            Self::InvalidData => tr("invalid vault data", "dati del vault non validi"),
        };
        f.write_str(message)
    }
}

impl std::error::Error for FormatError {}

pub fn header(salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&[VERSION, 2, 0x13, 1]); // Argon2id, Argon2 v19, AES-256-GCM
    for parameter in [MEMORY_KIB, ITERATIONS, PARALLELISM] {
        header.extend_from_slice(&parameter.to_le_bytes());
    }
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    header
}

/// Only the exact v3 profile is accepted, before any expensive derivation:
/// weakened or excessive costs never reach the KDF.
pub fn validate_header(encrypted: &[u8]) -> Result<(), FormatError> {
    if encrypted.len() < HEADER_LEN + TAG_LEN
        || encrypted.len() as u64 > MAX_SNAPSHOT_BYTES
        || encrypted[..SALT_START] != header(&[0; SALT_LEN], &[0; NONCE_LEN])[..SALT_START]
    {
        return Err(FormatError::InvalidFormat);
    }
    Ok(())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// The derived key of one vault. Every copy of a vault shares its salt, which
/// also identifies the vault across devices. Cloning lets a background job
/// authenticate downloads; every clone is wiped when dropped.
#[derive(Clone)]
pub struct VaultKey {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
}

impl VaultKey {
    pub fn derive(
        password: &str,
        salt: [u8; SALT_LEN],
        keyfile: &KeyFile,
    ) -> Result<Self, FormatError> {
        let mut key = Zeroizing::new([0u8; 32]);
        let _guard = KDF_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
            .map_err(|_| FormatError::KeyDerivation)?;
        let mut memory = Zeroizing::new(Vec::new());
        memory
            .try_reserve_exact(params.block_count())
            .map_err(|_| FormatError::KeyDerivation)?;
        memory.resize(params.block_count(), Block::default());
        // RFC 9106 secret input K: both independent factors enter the KDF itself.
        // Neither a password verifier nor a key-file verifier is stored in the vault.
        Argon2::new_with_secret(
            keyfile.secret(),
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        )
        .map_err(|_| FormatError::KeyDerivation)?
        .hash_password_into_with_memory(
            password.as_bytes(),
            &salt,
            key.as_mut_slice(),
            memory.as_mut_slice(),
        )
        .map_err(|_| FormatError::KeyDerivation)?;
        Ok(Self { key, salt })
    }

    /// Key for a new vault, with a fresh random salt.
    pub fn generate(password: &str, keyfile: &KeyFile) -> Result<Self, FormatError> {
        Self::derive(password, random_bytes(), keyfile)
    }

    /// Key for an existing copy, using the salt stored in its header.
    pub fn for_snapshot(
        encrypted: &[u8],
        password: &str,
        keyfile: &KeyFile,
    ) -> Result<Self, FormatError> {
        validate_header(encrypted)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&encrypted[SALT_START..NONCE_START]);
        Self::derive(password, salt, keyfile)
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    pub fn vault_id(&self) -> String {
        limits::hex(&self.salt)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn raw(&self) -> &[u8; 32] {
        &self.key
    }

    fn cipher(&self) -> Result<Aes256Gcm, FormatError> {
        Aes256Gcm::new_from_slice(self.key.as_slice()).map_err(|_| FormatError::Encryption)
    }

    /// Encrypts with a fresh random nonce.
    pub fn seal(&self, data: &VaultData) -> Result<Vec<u8>, FormatError> {
        if data.lineage.len() > MAX_LINEAGE {
            return Err(FormatError::InvalidData);
        }
        let nonce = random_bytes::<NONCE_LEN>();
        let plaintext =
            Zeroizing::new(serde_json::to_vec(data).map_err(|_| FormatError::InvalidData)?);
        if plaintext.len() as u64 + (HEADER_LEN + TAG_LEN) as u64 > MAX_SNAPSHOT_BYTES {
            return Err(FormatError::InvalidData);
        }
        let mut output = header(&self.salt, &nonce);
        let ciphertext = self
            .cipher()?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &output,
                },
            )
            .map_err(|_| FormatError::Encryption)?;
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Authenticates and decrypts a copy of this vault, then checks that its
    /// revision metadata is well formed and belongs to this vault.
    pub fn open(&self, encrypted: &[u8]) -> Result<VaultData, FormatError> {
        validate_header(encrypted)?;
        if encrypted[SALT_START..NONCE_START] != self.salt {
            return Err(FormatError::InvalidFormat);
        }
        let plaintext = Zeroizing::new(
            self.cipher()?
                .decrypt(
                    Nonce::from_slice(&encrypted[NONCE_START..HEADER_LEN]),
                    Payload {
                        msg: &encrypted[HEADER_LEN..],
                        aad: &encrypted[..HEADER_LEN],
                    },
                )
                .map_err(|_| FormatError::InvalidPasswordOrCorrupted)?,
        );
        let data: VaultData =
            serde_json::from_slice(&plaintext).map_err(|_| FormatError::InvalidData)?;
        if let Some(revision) = &data.revision
            && (revision.vault_id != self.vault_id()
                || !limits::valid_id(&revision.id)
                || revision.parents.len() > MAX_PARENTS
                || revision.device.len() > 128
                || revision
                    .parents
                    .iter()
                    .any(|id| !limits::valid_id(id) || id == &revision.id))
        {
            return Err(FormatError::InvalidData);
        }
        let mut seen = std::collections::BTreeSet::new();
        if data.lineage.len() > MAX_LINEAGE
            || data.revision.is_none() && !data.lineage.is_empty()
            || data.lineage.iter().any(|link| {
                !limits::valid_id(&link.id)
                    || !seen.insert(&link.id)
                    || data
                        .revision
                        .as_ref()
                        .is_some_and(|revision| revision.id == link.id)
                    || link.parents.len() > MAX_PARENTS
                    || link
                        .parents
                        .iter()
                        .any(|id| !limits::valid_id(id) || id == &link.id)
            })
        {
            return Err(FormatError::InvalidData);
        }
        Ok(data)
    }

    /// The authenticated revision and ancestry of a synchronized copy.
    pub fn read_sync_metadata(
        &self,
        encrypted: &[u8],
    ) -> Result<(Revision, Vec<RevisionLink>), FormatError> {
        let mut data = self.open(encrypted)?;
        let revision = data.revision.take().ok_or(FormatError::InvalidData)?;
        Ok((revision, std::mem::take(&mut data.lineage)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Credential;

    const FIXTURE_PASSWORD: &str = "public fixture master password";

    #[test]
    fn the_public_v3_fixture_opens_with_both_factors_only() {
        let bytes = include_bytes!("../tests/fixtures/vault-v3");
        assert_eq!(&bytes[..12], b"SEKEEPER\x03\x02\x13\x01");
        let key = VaultKey::for_snapshot(bytes, FIXTURE_PASSWORD, &KeyFile::test_key()).unwrap();
        let data = key.open(bytes).unwrap();
        assert_eq!(data.credentials[0].password, "public-test-secret");
        let other = KeyFile::parse(KeyFile::new_file().unwrap().as_slice()).unwrap();
        let wrong = VaultKey::for_snapshot(bytes, FIXTURE_PASSWORD, &other).unwrap();
        assert_eq!(
            wrong.open(bytes).err(),
            Some(FormatError::InvalidPasswordOrCorrupted)
        );
    }

    #[test]
    fn sealed_copies_roundtrip_reject_tampering_and_other_vaults() {
        let key = VaultKey::generate("una passphrase di prova", &KeyFile::test_key()).unwrap();
        let mut data = VaultData::default();
        let mut entry = Credential::default();
        entry.description = "Posta".into();
        data.credentials.push(entry);
        let sealed = key.seal(&data).unwrap();
        assert_ne!(sealed, key.seal(&data).unwrap());
        assert_eq!(
            key.open(&sealed).unwrap().credentials[0].description,
            "Posta"
        );
        for offset in [0, 12, SALT_START, NONCE_START, HEADER_LEN, sealed.len() - 1] {
            let mut damaged = sealed.clone();
            damaged[offset] ^= 1;
            assert!(key.open(&damaged).is_err(), "offset {offset}");
        }
        let mut weakened = sealed.clone();
        weakened[12..16].copy_from_slice(&(19 * 1024u32).to_le_bytes());
        assert_eq!(
            VaultKey::for_snapshot(&weakened, "x", &KeyFile::test_key()).err(),
            Some(FormatError::InvalidFormat)
        );
        let other = VaultKey::generate("una passphrase di prova", &KeyFile::test_key()).unwrap();
        assert_eq!(other.open(&sealed).err(), Some(FormatError::InvalidFormat));
        assert_eq!(
            key.read_sync_metadata(&sealed).err(),
            Some(FormatError::InvalidData)
        );
    }

    #[test]
    fn errors_render_in_english_and_italian() {
        use crate::i18n::{Lang, with_lang};

        with_lang(Lang::En, || {
            assert_eq!(
                FormatError::InvalidPasswordOrCorrupted.to_string(),
                "wrong password or key file, or corrupted vault"
            );
            assert_eq!(
                FormatError::InvalidFormat.to_string(),
                "invalid or unsupported vault format: a v3 vault with a key file is required"
            );
            assert_eq!(
                FormatError::KeyDerivation.to_string(),
                "error deriving the key"
            );
            assert_eq!(
                FormatError::Encryption.to_string(),
                "error encrypting the vault"
            );
            assert_eq!(FormatError::InvalidData.to_string(), "invalid vault data");
        });
        with_lang(Lang::It, || {
            assert_eq!(
                FormatError::InvalidPasswordOrCorrupted.to_string(),
                "password o file chiave errati, oppure vault danneggiato"
            );
            assert_eq!(
                FormatError::InvalidFormat.to_string(),
                "formato del vault non valido o non supportato: serve un vault v3 con file chiave"
            );
            assert_eq!(
                FormatError::KeyDerivation.to_string(),
                "errore durante la derivazione della chiave"
            );
            assert_eq!(
                FormatError::Encryption.to_string(),
                "errore durante la cifratura del vault"
            );
            assert_eq!(
                FormatError::InvalidData.to_string(),
                "dati del vault non validi"
            );
        });
    }
}
