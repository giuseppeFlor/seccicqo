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
