//! Everything both Sekeeper applications must agree on: the v3 vault format,
//! the key file, the credential model and the revision history. No user
//! interface, file system or network code lives here, so the same audited
//! implementation serves the desktop and the mobile app.

pub mod catalog;
pub mod format;
pub mod i18n;
pub mod keyfile;
pub mod limits;
pub mod model;
pub mod setup;
pub mod transfer;
