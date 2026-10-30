#!/usr/bin/env python3
"""PoC: analisi degli SMS di uno smartphone Android alla ricerca di phishing (smishing).

Flusso:
  1. Estrae gli SMS dal telefono via ADB (content provider content://sms) oppure
     li legge da un file di dump già salvato.
  2. Per ogni messaggio estrae link e mittente.
  3. Applica una serie di euristiche (link accorciati, domini sospetti, brand
     imitati, testo che mette fretta, ecc.) e assegna un punteggio di rischio.
  4. Stampa un riepilogo e, se richiesto, salva un report JSON.

Solo libreria standard Python; per l'estrazione serve `adb` nel PATH con il
debug USB attivo sul telefono.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

# --------------------------------------------------------------------------
# Estrazione SMS
# --------------------------------------------------------------------------

# body per ultimo: è l'unico campo che può contenere virgole e a capo.
PROJECTION = "_id:address:date:type:body"
ROW_RE = re.compile(r"^Row: \d+ _id=", re.MULTILINE)
FIELDS_RE = re.compile(
    r"_id=(?P<id>[^,]*), address=(?P<address>.*?), date=(?P<date>\d*), "
    r"type=(?P<type>\d*), body=(?P<body>.*)",
    re.DOTALL,
)

SMS_TYPES = {"1": "ricevuto", "2": "inviato", "3": "bozza", "4": "in uscita", "5": "fallito", "6": "in coda"}


@dataclass
class Sms:
    id: str
    address: str
    date: str
    type: str
    body: str


def dump_from_adb(serial: str | None = None) -> str:
    """Legge tutti gli SMS dal telefono collegato via ADB."""
    adb = shutil.which("adb")
    if not adb:
        sys.exit("adb non trovato nel PATH: installa le Android platform-tools.")
    cmd = [adb]
    if serial:
        cmd += ["-s", serial]
    cmd += ["shell", "content", "query", "--uri", "content://sms", "--projection", PROJECTION]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0 or "Error" in res.stdout[:200]:
        sys.exit(f"Errore durante la lettura degli SMS via adb:\n{res.stderr or res.stdout}")
    return res.stdout


def parse_content_query(raw: str) -> list[Sms]:
    """Converte l'output di `adb shell content query` in una lista di Sms."""
    starts = [m.start() for m in ROW_RE.finditer(raw)] + [len(raw)]
    out = []
    for a, b in zip(starts, starts[1:]):
        chunk = raw[a:b].rstrip("\r\n")
        m = FIELDS_RE.search(chunk)
        if not m:
            continue
        d = m.groupdict()
        out.append(Sms(d["id"], d["address"], d["date"], d["type"], d["body"]))
    return out


def load_messages(path: str) -> list[Sms]:
    """Carica un dump: output di `content query` (.txt) oppure JSON [{address, body, ...}]."""
    with open(path, encoding="utf-8", errors="replace") as f:
        raw = f.read()
    if raw.lstrip().startswith("["):
        return [
            Sms(str(m.get("id", i)), m.get("address", ""), str(m.get("date", "")), str(m.get("type", "1")), m.get("body", ""))
            for i, m in enumerate(json.loads(raw))
        ]
    return parse_content_query(raw)


# --------------------------------------------------------------------------
# Analisi
# --------------------------------------------------------------------------

URL_RE = re.compile(
    r"(?:(?:https?://|www\.)[^\s<>\"']+)"
    r"|(?:\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,24}/[^\s<>\"']*)",
    re.IGNORECASE,
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "t.ly", "rebrand.ly", "s.id", "tiny.cc", "bl.ink", "v.gd",
    "qrco.de", "short.io", "linktr.ee",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "info", "click", "link", "live", "shop",
    "icu", "buzz", "cfd", "sbs", "rest", "monster", "support", "help", "app", "vip",
    "work", "loan", "gq", "tk", "ml", "cf", "ga", "zip", "mov",
}

# Brand spesso imitati in Italia -> domini ufficiali (suffissi ammessi).
BRANDS = {
    "poste": ["poste.it", "posteitaliane.it", "postepay.it"],
    "postepay": ["poste.it", "postepay.it"],
    "bancoposta": ["poste.it"],
    "intesa": ["intesasanpaolo.com", "intesasanpaolo.it"],
    "sanpaolo": ["intesasanpaolo.com", "intesasanpaolo.it"],
    "unicredit": ["unicredit.it", "unicredit.eu"],
    "bper": ["bper.it"],
    "mps": ["mps.it"],
    "fineco": ["finecobank.com", "fineco.it"],
    "nexi": ["nexi.it"],
    "inps": ["inps.it"],
    "agenziaentrate": ["agenziaentrate.gov.it"],
    "entrate": ["agenziaentrate.gov.it"],
    "brt": ["brt.it"],
    "bartolini": ["brt.it"],
    "gls": ["gls-italy.com", "gls-group.com", "gls-group.eu"],
    "dhl": ["dhl.com", "dhl.it"],
    "sda": ["sda.it"],
    "ups": ["ups.com"],
    "amazon": ["amazon.it", "amazon.com", "amzn.to", "amzn.eu"],
    "netflix": ["netflix.com"],
    "paypal": ["paypal.com", "paypal.it"],
    "apple": ["apple.com"],
    "icloud": ["icloud.com", "apple.com"],
    "telepass": ["telepass.com"],
    "enel": ["enel.it", "enel.com"],
    "tim": ["tim.it"],
    "vodafone": ["vodafone.it"],
    "windtre": ["windtre.it"],
    "iliad": ["iliad.it"],
    "spid": ["spid.gov.it", "agid.gov.it"],
    "whatsapp": ["whatsapp.com", "wa.me"],
}

URGENCY_PATTERNS = [
    r"\bbloccat[oa]\b", r"\bsospes[oa]\b", r"\bdisattivat[oa]\b", r"\bscadut[oa]\b",
    r"\bentro (?:24|48) ?ore\b", r"\bimmediatamente\b", r"\burgente\b", r"\bultimo avviso\b",
    r"\bverific(?:a|are|ate)\b", r"\baggiorn(?:a|are)\b", r"\bconferm(?:a|are)\b",
    r"\bclicca\b", r"\baccedi\b", r"\baccesso (?:anomalo|non autorizzato|sospetto)\b",
    r"\bpacco\b.*\b(?:giacenza|sospeso|fermo|spedizione)\b", r"\bin giacenza\b",
    r"\bspese di (?:spedizione|sdoganamento)\b", r"\brimborso\b", r"\bhai vinto\b",
    r"\bpremio\b", r"\bbonifico\b.*\b(?:non autorizzato|annulla)\b", r"\bcarta\b.*\b(?:bloccata|sospesa)\b",
    r"\bcodice\b.*\b(?:otp|sicurezza)\b", r"\bdati (?:personali|bancari)\b",
    r"\b(?:mamma|pap[aà])\b.*\bnuovo numero\b", r"\bnuovo numero\b",
]
URGENCY_RE = [re.compile(p, re.IGNORECASE) for p in URGENCY_PATTERNS]


@dataclass
class Finding:
    sms_id: str
    sender: str
    date: str
    body: str
    urls: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    score: int = 0

    @property
    def verdict(self) -> str:
        if self.score >= 6:
            return "PHISHING PROBABILE"
        if self.score >= 3:
            return "SOSPETTO"
        return "ok"


def host_of(url: str) -> str:
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return host


def is_official(host: str, domains: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def analyze_url(url: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    host = host_of(url)
    if not host:
        return hits
    labels = host.split(".")
    tld = labels[-1]
    base = ".".join(labels[-2:])

    if base in SHORTENERS or host in SHORTENERS:
        hits.append((3, f"link accorciato ({host}) che nasconde la destinazione"))
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        hits.append((4, f"link verso indirizzo IP nudo ({host})"))
    if "xn--" in host:
        hits.append((4, f"dominio punycode/omografo ({host})"))
    if tld in SUSPICIOUS_TLDS:
        hits.append((2, f"estensione di dominio spesso abusata (.{tld})"))
    if url.lower().startswith("http://"):
        hits.append((1, "link non cifrato (http)"))
    if "@" in urlsplit(url if "://" in url else "http://" + url).netloc:
        hits.append((4, "URL con '@' per mascherare il dominio reale"))
    if len(labels) >= 5:
        hits.append((1, f"molti sottodomini ({host})"))
    if host.count("-") >= 2:
        hits.append((1, f"dominio con molti trattini ({host})"))

    compact = host.replace("-", "").replace(".", "")
    for brand, official in BRANDS.items():
        if brand in compact and not is_official(host, official):
            # evita falsi positivi su brand corti che compaiono dentro altre parole
            if len(brand) <= 3 and not re.search(rf"(?:^|[.-]){brand}(?:[.-]|$)", host):
                continue
            hits.append((5, f"il dominio richiama '{brand}' ma non è un dominio ufficiale ({host})"))
            break
    return hits


def analyze(sms: Sms) -> Finding:
    f = Finding(sms.id, sms.address, fmt_date(sms.date), sms.body)
    f.urls = [u.rstrip(".,;:!?)") for u in URL_RE.findall(sms.body)]

    for url in f.urls:
        for pts, why in analyze_url(url):
            f.score += pts
            f.reasons.append(why)

    urg = sorted({m.group(0).lower() for r in URGENCY_RE for m in [r.search(sms.body)] if m})
    if urg:
        pts = min(len(urg), 3)
        f.score += pts
        f.reasons.append("linguaggio di urgenza/pressione: " + ", ".join(urg))

    # mittente
    addr = sms.address.strip()
    if f.urls and re.fullmatch(r"\+?\d{8,15}", addr):
        f.score += 1
        f.reasons.append("link inviato da un numero di cellulare privato (le aziende usano un nome mittente)")
    if addr and not addr.startswith("+39") and re.fullmatch(r"\+\d{8,15}", addr):
        f.score += 1
        f.reasons.append(f"numero estero ({addr})")
    for brand, official in BRANDS.items():
        if brand in sms.body.lower().replace(" ", "") and f.urls:
            if not any(is_official(host_of(u), official) for u in f.urls) and len(brand) > 3:
                f.score += 2
                f.reasons.append(f"il testo cita '{brand}' ma il link non porta a un suo dominio ufficiale")
                break

    # dedup motivi mantenendo l'ordine
    f.reasons = list(dict.fromkeys(f.reasons))
    return f


def fmt_date(ms: str) -> str:
    try:
        return dt.datetime.fromtimestamp(int(ms) / 1000).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError):
        return ms


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Controllo phishing sugli SMS di un telefono Android")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--adb", action="store_true", help="estrai gli SMS dal telefono collegato via ADB")
    src.add_argument("--input", metavar="FILE", help="analizza un dump già salvato (.txt di content query o .json)")
    p.add_argument("-s", "--serial", help="seriale del dispositivo adb (se ne hai più di uno collegato)")
    p.add_argument("--save-dump", metavar="FILE", help="salva il dump grezzo degli SMS estratti via adb")
    p.add_argument("--json", metavar="FILE", help="salva il report completo in JSON")
    p.add_argument("--all", action="store_true", help="mostra anche i messaggi senza segnalazioni")
    p.add_argument("--include-sent", action="store_true", help="analizza anche gli SMS inviati (di default solo ricevuti)")
    args = p.parse_args(argv)

    if args.adb:
        raw = dump_from_adb(args.serial)
        if args.save_dump:
            with open(args.save_dump, "w", encoding="utf-8") as fh:
                fh.write(raw)
        messages = parse_content_query(raw)
    else:
        messages = load_messages(args.input)

    if not args.include_sent:
        messages = [m for m in messages if m.type in ("", "1")]

    findings = [analyze(m) for m in messages]
    findings.sort(key=lambda x: x.score, reverse=True)
    flagged = [f for f in findings if f.score >= 3]

    print(f"\nSMS analizzati: {len(findings)}  |  con link: {sum(1 for f in findings if f.urls)}"
          f"  |  sospetti: {sum(1 for f in flagged if f.verdict == 'SOSPETTO')}"
          f"  |  phishing probabile: {sum(1 for f in flagged if f.verdict == 'PHISHING PROBABILE')}\n")

    for f in (findings if args.all else flagged):
        print("=" * 78)
        print(f"[{f.verdict}] punteggio {f.score}  |  da: {f.sender}  |  {f.date}")
        print("-" * 78)
        print(f.body.strip())
        if f.urls:
            print("\nLink: " + ", ".join(f.urls))
        for r in f.reasons:
            print(f"  - {r}")
    if not flagged:
        print("Nessun SMS sospetto trovato.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([{**asdict(f), "verdict": f.verdict} for f in findings], fh, ensure_ascii=False, indent=2)
        print(f"\nReport JSON salvato in {args.json}")
    return 1 if any(f.verdict == "PHISHING PROBABILE" for f in flagged) else 0


if __name__ == "__main__":
    sys.exit(main())
