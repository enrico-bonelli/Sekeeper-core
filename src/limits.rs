use sha2::{Digest, Sha256};

pub const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_VERSIONS: usize = 2048;
pub const RETAINED_VERSIONS: usize = 30;
pub const MAX_LINEAGE: usize = 65_536;
pub const MAX_PARENTS: usize = 128;

/// Revision identifiers: 128 random bits as lowercase hexadecimal.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn fingerprint(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
