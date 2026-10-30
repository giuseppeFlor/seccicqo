# seccicqo

Suite per aiutare utenti non esperti ad analizzare uno smartphone Android e capire se contiene malware o tentativi di phishing.

## PoC 1: controllo phishing negli SMS

`sms_phishing/check_sms.py` legge gli SMS del telefono via ADB e segnala quelli sospetti.

### Requisiti
- Python 3.9+ (nessuna libreria esterna)
- [Android platform-tools](https://developer.android.com/tools/releases/platform-tools) (`adb`) nel PATH
- Sul telefono: *Opzioni sviluppatore → Debug USB* attivo, e autorizzare il PC quando compare il popup

### Uso
```bash
adb devices                                   # il telefono deve risultare "device"
python3 sms_phishing/check_sms.py --adb --save-dump sms.txt --json report.json
```
Oppure su un dump già salvato:
```bash
python3 sms_phishing/check_sms.py --input sms_phishing/samples/sms_dump_esempio.txt
```
Opzioni utili: `--all` mostra anche i messaggi puliti, `--include-sent` analizza anche gli SMS inviati, `-s SERIALE` sceglie il dispositivo.

Il dump è prodotto con:
```bash
adb shell content query --uri content://sms --projection _id:address:date:type:body
```

### Cosa controlla
| Controllo | Esempio |
|---|---|
| Link accorciati | `bit.ly/…`, `cutt.ly/…` |
| Link a IP nudo | `http://185.23.44.10/…` |
| Domini punycode / omografi | `xn--pste-…` |
| Estensioni abusate | `.top`, `.xyz`, `.click` |
| Brand imitato nel dominio | `poste-italiane-verifica.top` |
| Testo che cita un brand ma link non ufficiale | "INPS" + link non `inps.it` |
| Linguaggio di urgenza | "conto sospeso", "entro 24 ore", "pacco in giacenza" |
| Mittente | link da cellulare privato, numero estero, truffa "mamma, nuovo numero" |

Ogni segnale aggiunge punti: da 3 il messaggio è **SOSPETTO**, da 6 **PHISHING PROBABILE**. Il comando esce con codice 1 se trova almeno un phishing probabile.

### Test
```bash
python3 -m unittest tests.test_check_sms -v
```

### Limiti (PoC)
Analisi solo euristica e offline: non segue i link accorciati e non consulta blocklist (es. URLhaus, Google Safe Browsing, VirusTotal). Su alcuni Android recenti la lettura di `content://sms` via adb può essere limitata.

## Avvio con Docker

Ogni componente gira nel suo container (`docker-compose.yml`):

| Container | Cosa fa | Isolamento |
|---|---|---|
| `adb` | server ADB, l'unico che parla col telefono | porta 5037 solo sulla rete interna dei container |
| `sms-phishing` | `check_sms.py`, legge gli SMS tramite il container `adb` | filesystem in sola lettura, nessuna capability, scrive solo in `./data` |
| `sandbox` | ambiente protetto per analizzare APK e file sospetti | vedi sotto |

```bash
docker compose build
docker compose run --rm sms-phishing          # risultato in ./data/report.json e ./data/sms.txt
docker compose run --rm sms-phishing --input /data/sms.txt --all   # rianalizza un dump già salvato
```
Su Linux i file prodotti appartengono all'utente con UID 1000; se il tuo è diverso:
`export SECCICQO_UID=$(id -u) SECCICQO_GID=$(id -g)`.

### Collegare il telefono
- **Linux, cavo USB**: `docker compose -f docker-compose.yml -f docker-compose.usb.yml up -d adb`
- **Qualsiasi sistema, debug wireless** (Android 11+, *Opzioni sviluppatore → Debug wireless*):
  ```bash
  docker compose up -d adb
  docker compose exec adb adb pair IP_TELEFONO:PORTA_ABBINAMENTO   # chiede il codice mostrato sul telefono
  docker compose exec adb adb connect IP_TELEFONO:PORTA
  ```
- **Windows/macOS, cavo USB**: Docker Desktop non passa l'USB ai container. Usa l'adb installato sul PC,
  in ascolto anche verso i container, e salta il container `adb`:
  ```powershell
  adb kill-server; adb -a nodaemon server start      # lascia aperta questa finestra
  # in un altro terminale (PowerShell)
  $env:ADB_SERVER_SOCKET="tcp:host.docker.internal:5037"; docker compose run --rm --no-deps sms-phishing
  ```
  Con `-a` il server adb accetta connessioni da tutta la rete: chiudilo quando hai finito e
  verifica che il firewall di Windows non esponga la porta 5037 all'esterno.

## Sandbox per l'analisi di malware

Il container `sandbox` serve a esaminare file sospetti (es. un APK scaricato da un SMS o estratto
dal telefono) **senza eseguirli**. Fa un triage statico: hash da cercare su VirusTotal/MalwareBazaar,
tipo di file, permessi e componenti dell'APK (androguard), URL e IP contenuti nel codice, regole YARA
(`docker/sandbox/rules/`), e un punteggio di rischio.

```bash
cp ~/Download/app_sospetta.apk sandbox/samples/
docker compose run --rm sandbox                     # report in sandbox/reports/<sha256>.json
docker compose run --rm --entrypoint bash sandbox   # shell per analisi manuale (strings, unzip -l, ...)
```

Protezioni applicate dal compose:
- `network_mode: none`: nessuna interfaccia di rete oltre a loopback, il campione non può contattare nessuno;
- root filesystem in sola lettura, campioni montati in sola lettura, unico punto scrivibile `sandbox/reports`;
- `/tmp` in RAM con `noexec`: non si può eseguire nulla di scritto lì;
- `cap_drop: ALL` e `no-new-privileges`: nessun privilegio, neanche tramite binari setuid;
- utente non root, limiti su processi (128), memoria (1 GB), CPU (1) e nessun core dump.

È isolamento a livello di container, sufficiente per l'analisi statica. **Non** usarlo per eseguire
malware (analisi dinamica): per quello serve una macchina virtuale dedicata o un emulatore Android
senza rete, perché un container condivide il kernel con il tuo PC.
I campioni e i report sono esclusi da git (`.gitignore`): non caricare mai malware nel repository.
