# sekeeper-core

> **[Leggi in italiano](README.it.md)**

The shared core library for [Sekeeper](../sekeeper): the v3 vault format, key file,
credential model, revision history, device setup transfer, CSV import/export, and
internationalization. It contains no UI, filesystem access, or networking code, so
the exact same implementation powers both the Linux desktop app and the Android app.

| Module | Purpose |
| --- | --- |
| `format` | v3 header, Argon2id with the key file as secret input `K`, AES-256-GCM, and metadata validation |
| `keyfile` | `SEKEY001` format: creation, verification, and QR transfer encoding |
| `setup` | Desktop-to-phone setup QR payload (key file + S3 destination) |
| `catalog` | Revision DAG, current head selection, conflicts, and version comparison |
| `model` | Credentials, revisions, and search |
| `transfer` | CSV import and export (accepting both English and Italian column headers) |
| `limits` | Defensive size/count limits and revision identifiers |
| `i18n` | Automatic English/Italian localization based on environment locale (Italian when detected, English fallback) |

Consumer apps depend on this crate via a local path dependency, with this repository
cloned next to theirs (`../sekeeper-core`).

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

The test suite opens the public fixture `tests/fixtures/vault-v3` with password
`public fixture master password` and key file `tests/fixtures/public-test.key`: any
accidental breaking change to the vault format will fail this test immediately.

## License

MIT.
