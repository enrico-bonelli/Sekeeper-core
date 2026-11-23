# sekeeper-core

> **[Read in English](README.md)**

La parte di [Sekeeper](../sekeeper) che tutte le app devono condividere: il formato
del vault v3, il file chiave, il modello delle credenziali, la cronologia delle
versioni, il trasferimento configurazione, l'import/export CSV e la localizzazione.
Non contiene interfaccia grafica, accesso ai file o codice di rete, così la stessa
implementazione serve l'app desktop e quella Android.

| Modulo | Contenuto |
| --- | --- |
| `format` | Intestazione v3, Argon2id con il file chiave come input segreto K, AES-256-GCM e validazione dei metadati |
| `keyfile` | Formato `SEKEY001`: creazione, verifica del contenuto e formato QR di trasferimento |
| `setup` | Payload QR di configurazione desktop → telefono (file chiave + destinazione S3) |
| `catalog` | Grafo delle revisioni, versione corrente, conflitti e confronto tra versioni |
| `model` | Credenziali, revisioni e ricerca |
| `transfer` | Importazione ed esportazione CSV (con riconoscimento delle intestazioni sia inglesi sia italiane) |
| `limits` | Limiti difensivi e identificativi |
| `i18n` | Localizzazione automatica Inglese/Italiano in base alla lingua dell'ambiente (italiano se rilevato, altrimenti inglese) |

Le app la usano come dipendenza di percorso, con questo repository clonato accanto
al loro (`../sekeeper-core`).

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

I test aprono la fixture pubblica `tests/fixtures/vault-v3`, con la password
`public fixture master password` e il file `tests/fixtures/public-test.key`: un
formato che cambiasse per errore non riuscirebbe più ad aprirla.

## Licenza

MIT.
