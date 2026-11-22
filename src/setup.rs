//! Everything a new device needs, carried by one QR code from the desktop:
//! the key file and the S3 destination with its access keys. The master
//! password is never part of it.

use crate::keyfile::{FILE_LEN, KeyFile, KeyFileError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SETUP_PREFIX: &str = "SEKEEPER-SETUP:1:";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SetupError {
    #[error("questo QR code non contiene una configurazione di Sekeeper")]
    Invalid,
    #[error("il file chiave nel QR code non è valido")]
    KeyFile,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DeviceSetup {
    #[serde(rename = "k")]
    keyfile: String,
    #[serde(rename = "b")]
    pub bucket: String,
    #[serde(rename = "r")]
    pub region: String,
    #[serde(rename = "p")]
    pub prefix: String,
    #[serde(rename = "a")]
    pub access_key: String,
    #[serde(rename = "s")]
    pub secret_key: String,
}

fn bounded(value: &str, limit: usize) -> bool {
    value.len() <= limit && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

impl DeviceSetup {
    pub fn new(
        keyfile: &[u8],
        bucket: &str,
        region: &str,
        prefix: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self, SetupError> {
        let text = KeyFile::transfer_text(keyfile).map_err(|_| SetupError::KeyFile)?;
        let setup = Self {
            keyfile: text[crate::keyfile::TRANSFER_PREFIX.len()..].to_string(),
            bucket: bucket.into(),
            region: region.into(),
            prefix: prefix.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
        };
        setup.check()?;
        Ok(setup)
    }

    // Shape only: each application validates the destination with its own
    // S3 rules before using it.
    fn check(&self) -> Result<(), SetupError> {
        let ok = bounded(&self.bucket, 63)
            && bounded(&self.region, 32)
            && bounded(&self.prefix, 256)
            && bounded(&self.access_key, 128)
            && bounded(&self.secret_key, 256)
            && self.access_key.is_empty() == self.secret_key.is_empty();
        if ok { Ok(()) } else { Err(SetupError::Invalid) }
    }

    pub fn to_text(&self) -> Zeroizing<String> {
        let json = Zeroizing::new(serde_json::to_string(self).expect("serializzazione"));
        Zeroizing::new(format!("{SETUP_PREFIX}{}", json.as_str()))
    }

    pub fn from_text(text: &str) -> Result<Self, SetupError> {
        let json = text
            .trim()
            .strip_prefix(SETUP_PREFIX)
            .ok_or(SetupError::Invalid)?;
        let setup: Self = serde_json::from_str(json).map_err(|_| SetupError::Invalid)?;
        setup.check()?;
        setup.keyfile()?;
        Ok(setup)
    }

    /// The verified key file.
    pub fn keyfile(&self) -> Result<Zeroizing<[u8; FILE_LEN]>, SetupError> {
        let text = Zeroizing::new(format!(
            "{}{}",
            crate::keyfile::TRANSFER_PREFIX,
            self.keyfile
        ));
        KeyFile::from_transfer_text(&text).map_err(|_: KeyFileError| SetupError::KeyFile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = include_bytes!("../tests/fixtures/public-test.key");

    #[test]
    fn a_complete_setup_roundtrips_and_fits_a_readable_qr_code() {
        let setup = DeviceSetup::new(
            KEY,
            "sekeeper-example",
            "eu-central-1",
            "sekeeper/personale/",
            "AKIAEXAMPLEONLY123456",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        .unwrap();
        let text = setup.to_text();
        assert!(text.starts_with(SETUP_PREFIX));
        // Version 15 at level M holds 412 bytes: keep well below.
        assert!(text.len() < 340, "{}", text.len());
        let back = DeviceSetup::from_text(&text).unwrap();
        assert_eq!(back.keyfile().unwrap().as_slice(), KEY);
        assert_eq!(
            (
                back.bucket.as_str(),
                back.prefix.as_str(),
                back.access_key.as_str()
            ),
            (
                "sekeeper-example",
                "sekeeper/personale/",
                "AKIAEXAMPLEONLY123456"
            )
        );
    }

    #[test]
    fn damaged_or_foreign_codes_are_rejected() {
        let setup = DeviceSetup::new(KEY, "b", "r", "p/", "", "").unwrap();
        let text = setup.to_text();
        assert!(DeviceSetup::from_text(&text).is_ok());
        assert_eq!(
            DeviceSetup::from_text("https://example.org").err(),
            Some(SetupError::Invalid)
        );
        let damaged = text.replacen("53454B4559", "53454B4558", 1);
        assert_eq!(
            DeviceSetup::from_text(&damaged).err(),
            Some(SetupError::KeyFile)
        );
        assert!(DeviceSetup::new(&KEY[..71], "b", "r", "p/", "", "").is_err());
        assert!(DeviceSetup::new(KEY, "b", "r", "p/", "AKIA", "").is_err());
        assert!(DeviceSetup::new(KEY, "b c", "r", "p/", "", "").is_err());
    }
}
