# sekeeper-core

La parte di [Sekeeper](../sekeeper) che tutte le app devono condividere: il formato
del vault v3, il file chiave, il modello delle credenziali e la cronologia delle
versioni. Non contiene interfaccia grafica, accesso ai file o codice di rete, così
la stessa implementazione serve l'app desktop e quella Android.

| Modulo | Contenuto |
| --- | --- |
| `format` | Intestazione v3, Argon2id con il file chiave come input segreto K, AES-256-GCM e validazione dei metadati |
| `keyfile` | Formato `SEKEY001`: creazione e verifica del contenuto |
| `catalog` | Grafo delle revisioni, versione corrente, conflitti e confronto tra versioni |
| `model` | Credenziali, revisioni e ricerca |
| `transfer` | Importazione ed esportazione CSV |
| `limits` | Limiti difensivi e identificativi |

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
