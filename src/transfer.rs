//! CSV exchange with other password managers. Columns are recognised by name,
//! so files from common applications can be imported as they are.

use crate::i18n::{is_italian, tr};
use crate::model::Credential;
use std::fmt;
use zeroize::Zeroizing;

pub const MAX_IMPORT_BYTES: u64 = 8 * 1024 * 1024;
const COLUMNS: [&str; 7] = [
    "description",
    "username",
    "password",
    "address",
    "notes",
    "created_at",
    "updated_at",
];
const DESCRIPTION: [&str; 5] = ["description", "descrizione", "title", "name", "nome"];
const USERNAME: [&str; 5] = ["username", "login_username", "user", "login", "utente"];
const PASSWORD: [&str; 2] = ["password", "login_password"];
const ADDRESS: [&str; 6] = ["address", "indirizzo", "url", "login_uri", "uri", "website"];
const NOTES: [&str; 4] = ["notes", "note", "notes_plain", "extra"];

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    Encoding,
    UnterminatedQuote,
    MissingColumns,
    MissingDescription(usize),
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding => f.write_str(tr(
                "the file is not UTF-8: save it with UTF-8 encoding and try again",
                "il file non è UTF-8: salvalo in questa codifica e riprova",
            )),
            Self::UnterminatedQuote => f.write_str(tr(
                "invalid CSV: unterminated quote",
                "CSV non valido: virgolette non chiuse",
            )),
            Self::MissingColumns => f.write_str(tr(
                "unrecognized CSV: at least description and password columns are required",
                "CSV non riconosciuto: servono almeno le colonne descrizione e password",
            )),
            Self::MissingDescription(line) => {
                if is_italian() {
                    write!(f, "riga {line} del CSV senza descrizione")
                } else {
                    write!(f, "CSV row {line} is missing a description")
                }
            }
        }
    }
}

impl std::error::Error for TransferError {}

pub fn encode(credentials: &[Credential]) -> Zeroizing<String> {
    let mut output = Zeroizing::new(COLUMNS.join(",") + "\r\n");
    for credential in credentials {
        let date =
            |value: Option<u64>| Zeroizing::new(value.map_or(String::new(), |v| v.to_string()));
        let (created, updated) = (date(credential.created_at), date(credential.updated_at));
        let fields = [
            credential.description.as_str(),
            &credential.username,
            &credential.password,
            &credential.address,
            &credential.notes,
            &created,
            &updated,
        ];
        for (index, field) in fields.into_iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            if field.contains([',', '"', '\n', '\r']) {
                output.push('"');
                for character in field.chars() {
                    if character == '"' {
                        output.push('"');
                    }
                    output.push(character);
                }
                output.push('"');
            } else {
                output.push_str(field);
            }
        }
        output.push_str("\r\n");
    }
    output
}

fn records(text: &str) -> Result<Vec<Vec<Zeroizing<String>>>, TransferError> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = Zeroizing::new(String::new());
    let mut quoted = false;
    let mut characters = text.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(character) = characters.next() {
        match (quoted, character) {
            (true, '"') if characters.peek() == Some(&'"') => {
                characters.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (true, other) => field.push(other),
            (false, '"') if field.is_empty() => quoted = true,
            (false, ',') => record.push(std::mem::take(&mut field)),
            (false, '\r') if characters.peek() == Some(&'\n') => {}
            (false, '\n' | '\r') => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            (false, other) => field.push(other),
        }
    }
    if quoted {
        return Err(TransferError::UnterminatedQuote);
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

pub fn decode(bytes: &[u8]) -> Result<Vec<Credential>, TransferError> {
    let text = std::str::from_utf8(bytes).map_err(|_| TransferError::Encoding)?;
    let mut rows = records(text)?.into_iter();
    let header: Vec<String> = rows
        .next()
        .ok_or(TransferError::MissingColumns)?
        .iter()
        .map(|name| name.trim().to_lowercase())
        .collect();
    let column = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| header.iter().position(|column| column == name))
    };
    let (Some(description), Some(password)) = (column(&DESCRIPTION), column(&PASSWORD)) else {
        return Err(TransferError::MissingColumns);
    };
    let username = column(&USERNAME);
    let address = column(&ADDRESS);
    let notes = column(&NOTES);
    let created = column(&["created_at"]);
    let updated = column(&["updated_at"]);
    let mut credentials = Vec::new();
    for (index, row) in rows.enumerate() {
        if row.iter().all(|field| field.is_empty()) {
            continue;
        }
        let text = |column: Option<usize>| -> String {
            column
                .and_then(|column| row.get(column))
                .map_or(String::new(), |field| field.as_str().to_owned())
        };
        let date = |column: Option<usize>| text(column).parse::<u64>().ok();
        let credential = Credential {
            id: String::new(),
            description: text(Some(description)).trim().to_owned(),
            username: text(username).trim().to_owned(),
            password: text(Some(password)),
            address: text(address).trim().to_owned(),
            notes: text(notes),
            created_at: date(created),
            updated_at: date(updated),
        };
        if credential.description.is_empty() {
            // Header is line 1; the first record is reported as line 2.
            return Err(TransferError::MissingDescription(index + 2));
        }
        credentials.push(credential);
    }
    Ok(credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Credential {
        Credential {
            id: "not exported".into(),
            description: "Posta, \"personale\"".into(),
            username: "demo".into(),
            password: "segreto,con\"virgole".into(),
            address: "https://example.org".into(),
            notes: "prima riga\nseconda riga".into(),
            created_at: Some(1_700_000_000),
            updated_at: None,
        }
    }

    #[test]
    fn export_roundtrips_every_field_and_omits_internal_ids() {
        let encoded = encode(&[sample(), Credential::default()]);
        assert!(!encoded.contains("not exported"));
        let mut only = encode(&[sample()]);
        only.push_str("\r\n");
        let decoded = decode(only.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].same_content(&sample()));
        assert_eq!(decoded[0].created_at, Some(1_700_000_000));
        assert_eq!(decoded[0].updated_at, None);
        assert!(decoded[0].id.is_empty());
    }

    #[test]
    fn files_from_other_applications_are_recognised_by_column_name() {
        let chrome = "\u{feff}name,url,username,password,note\nBanca,https://b.example,io,pw,\n";
        let row = &decode(chrome.as_bytes()).unwrap()[0];
        assert_eq!(
            (
                row.description.as_str(),
                row.address.as_str(),
                row.username.as_str()
            ),
            ("Banca", "https://b.example", "io")
        );
        let keepass = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\r\n\
                       \"Root\",\"Posta\",\"io\",\"pw\",\"\",\"a\"\"b\"\r\n";
        let row = &decode(keepass.as_bytes()).unwrap()[0];
        assert_eq!(
            (row.description.as_str(), row.notes.as_str()),
            ("Posta", "a\"b")
        );
        let bitwarden = "name,notes,login_uri,login_username,login_password\nX,,u,io,pw";
        let row = &decode(bitwarden.as_bytes()).unwrap()[0];
        assert_eq!((row.username.as_str(), row.password.as_str()), ("io", "pw"));
    }

    #[test]
    fn unusable_files_are_rejected_with_a_reason() {
        let failure = |bytes: &[u8]| decode(bytes).err().unwrap();
        assert_eq!(failure(b""), TransferError::MissingColumns);
        assert_eq!(failure(b"a,b\n1,2\n"), TransferError::MissingColumns);
        assert_eq!(failure(&[0xff, 0xfe]), TransferError::Encoding);
        assert_eq!(
            failure(b"name,password\n\"a,b\n"),
            TransferError::UnterminatedQuote
        );
        assert_eq!(
            failure(b"name,password\nA,1\n,2\n"),
            TransferError::MissingDescription(3)
        );
    }

    #[test]
    fn italian_and_english_csv_headers_are_both_accepted() {
        let italian = "descrizione,utente,password,indirizzo,note\nPosta,mario,segreto,https://mail.example,appunto\n";
        let rows = decode(italian.as_bytes()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].description, "Posta");
        assert_eq!(rows[0].username, "mario");
        assert_eq!(rows[0].password, "segreto");
        assert_eq!(rows[0].address, "https://mail.example");
        assert_eq!(rows[0].notes, "appunto");

        let english = "description,username,password,address,notes\nMail,mario,secret,https://mail.example,note\n";
        let rows = decode(english.as_bytes()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].description, "Mail");
        assert_eq!(rows[0].username, "mario");
        assert_eq!(rows[0].password, "secret");
        assert_eq!(rows[0].address, "https://mail.example");
        assert_eq!(rows[0].notes, "note");
    }

    #[test]
    fn errors_render_in_english_and_italian() {
        use crate::i18n::{Lang, with_lang};

        with_lang(Lang::En, || {
            assert_eq!(
                TransferError::Encoding.to_string(),
                "the file is not UTF-8: save it with UTF-8 encoding and try again"
            );
            assert_eq!(
                TransferError::UnterminatedQuote.to_string(),
                "invalid CSV: unterminated quote"
            );
            assert_eq!(
                TransferError::MissingColumns.to_string(),
                "unrecognized CSV: at least description and password columns are required"
            );
            assert_eq!(
                TransferError::MissingDescription(3).to_string(),
                "CSV row 3 is missing a description"
            );
        });
        with_lang(Lang::It, || {
            assert_eq!(
                TransferError::Encoding.to_string(),
                "il file non è UTF-8: salvalo in questa codifica e riprova"
            );
            assert_eq!(
                TransferError::UnterminatedQuote.to_string(),
                "CSV non valido: virgolette non chiuse"
            );
            assert_eq!(
                TransferError::MissingColumns.to_string(),
                "CSV non riconosciuto: servono almeno le colonne descrizione e password"
            );
            assert_eq!(
                TransferError::MissingDescription(3).to_string(),
                "riga 3 del CSV senza descrizione"
            );
        });
    }
}
