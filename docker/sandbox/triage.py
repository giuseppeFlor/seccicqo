#!/usr/bin/env python3
"""Triage statico di campioni sospetti, pensato per girare nel container sandbox.

Per ogni file in input:
  - calcola gli hash (md5, sha1, sha256) da cercare su VirusTotal/MalwareBazaar;
  - riconosce il tipo con `file`;
  - se è un APK ne legge manifest, permessi e componenti con androguard;
  - estrae URL e indirizzi IP dalle stringhe (anche dentro i .dex);
  - applica le regole YARA in /opt/sandbox/rules.

Nessun campione viene eseguito: il codice legge solo i byte. Il report JSON
finisce in /reports/<sha256>.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

RULES_DIR = Path("/opt/sandbox/rules")
MAX_STRINGS_BYTES = 64 * 1024 * 1024  # non leggiamo più di 64 MB per file

URL_RE = re.compile(rb"https?://[\x21-\x7e]{4,200}")
IP_RE = re.compile(rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")

# Permessi che, insieme, sono tipici di banking trojan, spyware e SMS fraud.
DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": "può inviare SMS (anche a numeri a pagamento)",
    "android.permission.RECEIVE_SMS": "legge gli SMS in arrivo (es. codici OTP)",
    "android.permission.READ_SMS": "legge tutti gli SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "servizio di accessibilità: può leggere lo schermo e cliccare al posto tuo",
    "android.permission.SYSTEM_ALERT_WINDOW": "può disegnare finestre sopra altre app (overlay di phishing)",
    "android.permission.BIND_DEVICE_ADMIN": "amministratore del dispositivo: difficile da disinstallare",
    "android.permission.REQUEST_INSTALL_PACKAGES": "può installare altre app (dropper)",
    "android.permission.READ_CONTACTS": "legge la rubrica",
    "android.permission.READ_CALL_LOG": "legge il registro chiamate",
    "android.permission.RECORD_AUDIO": "può registrare audio",
    "android.permission.CAMERA": "può usare la fotocamera",
    "android.permission.ACCESS_FINE_LOCATION": "conosce la posizione precisa",
    "android.permission.QUERY_ALL_PACKAGES": "vede tutte le app installate (es. per cercare app bancarie)",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "legge tutte le notifiche",
    "android.permission.READ_PHONE_STATE": "legge identificativi del telefono",
}


def hashes(path: Path) -> dict[str, str]:
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for d in h.values():
                d.update(chunk)
    return {k: d.hexdigest() for k, d in h.items()}


def file_type(path: Path) -> str:
    if not shutil.which("file"):
        return "sconosciuto (comando file assente)"
    res = subprocess.run(["file", "-b", str(path)], capture_output=True, text=True)
    return res.stdout.strip()


def iocs(blobs: list[bytes]) -> dict[str, list[str]]:
    urls: set[str] = set()
    ips: set[str] = set()
    for b in blobs:
        urls.update(m.decode("ascii", "replace").rstrip("\"'),;") for m in URL_RE.findall(b))
        ips.update(m.decode() for m in IP_RE.findall(b))
    # scarta gli IP "di servizio" che compaiono ovunque
    ips = {ip for ip in ips if not ip.startswith(("0.", "127.", "255.")) and ip.count(".") == 3}
    return {"urls": sorted(urls)[:500], "ips": sorted(ips)[:500]}


def yara_matches(path: Path, blobs: list[bytes]) -> list[str]:
    """Applica le regole al file e ai contenuti già decompressi (es. classes.dex),
    perché dentro un APK il codice è compresso e le stringhe non sono visibili."""
    rules_files = sorted(RULES_DIR.glob("*.yar"))
    if not rules_files:
        return []
    try:
        import yara
    except ImportError:
        return []
    rules = yara.compile(filepaths={f.stem: str(f) for f in rules_files})
    matches = {m.rule for m in rules.match(str(path), timeout=60)}
    for b in blobs:
        matches.update(m.rule for m in rules.match(data=b, timeout=60))
    return sorted(matches)


def apk_info(path: Path) -> dict:
    try:
        from loguru import logger
        logger.remove()  # androguard è molto verboso
        from androguard.core.apk import APK
    except ImportError:
        return {"errore": "androguard non disponibile"}
    # APK malformati (spesso apposta, per rompere gli analizzatori) sono comuni
    # nei malware: qualunque errore di parsing diventa una nota nel report.
    try:
        apk = APK(str(path))
        perms = sorted(set(apk.get_permissions()))
        return {
            "package": apk.get_package(),
            "app_name": apk.get_app_name(),
            "version": apk.get_androidversion_name(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "firmato": apk.is_signed(),
            "permessi": perms,
            "permessi_pericolosi": {p: DANGEROUS_PERMISSIONS[p] for p in perms if p in DANGEROUS_PERMISSIONS},
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
            "providers": apk.get_providers(),
        }
    except Exception as exc:
        return {"errore": f"APK non leggibile: {exc!r}"}


def zip_blobs(path: Path) -> list[bytes]:
    """Legge in memoria (senza estrarli su disco) .dex e file di testo dell'archivio."""
    blobs: list[bytes] = []
    budget = MAX_STRINGS_BYTES
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if budget <= 0:
                break
            if info.filename.endswith((".dex", ".xml", ".json", ".js", ".html", ".txt", ".properties")) \
                    or info.filename.startswith("assets/"):
                if info.file_size > budget:
                    continue
                try:
                    blobs.append(zf.read(info))
                except Exception:
                    continue
                budget -= info.file_size
    return blobs


def risk(report: dict) -> tuple[int, list[str]]:
    score, reasons = 0, []
    apk = report.get("apk") or {}
    danger = apk.get("permessi_pericolosi") or {}
    for p, why in danger.items():
        score += 1
        reasons.append(f"{p.split('.')[-1]}: {why}")
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in danger and \
            "android.permission.SYSTEM_ALERT_WINDOW" in danger:
        score += 3
        reasons.append("accessibilità + overlay: combinazione tipica dei banking trojan")
    if {"android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"} <= danger.keys():
        score += 2
        reasons.append("legge e invia SMS: tipico di furto OTP / SMS a pagamento")
    for m in report.get("yara", []):
        score += 2
        reasons.append(f"regola YARA: {m}")
    if score >= 8:
        verdict = "ALTO RISCHIO"
    elif score >= 4:
        verdict = "SOSPETTO"
    else:
        verdict = "NESSUN SEGNALE FORTE"
    return score, [verdict] + reasons


def triage(path: Path, out_dir: Path) -> dict:
    report: dict = {"file": path.name, "dimensione": path.stat().st_size, **hashes(path), "tipo": file_type(path)}
    blobs: list[bytes] = []
    if zipfile.is_zipfile(path):
        try:
            blobs = zip_blobs(path)
        except zipfile.BadZipFile:
            pass
        with zipfile.ZipFile(path) as zf:
            if "AndroidManifest.xml" in zf.namelist():
                report["apk"] = apk_info(path)
    if not blobs:
        with path.open("rb") as fh:
            blobs = [fh.read(MAX_STRINGS_BYTES)]
    report.update(iocs(blobs))
    report["yara"] = yara_matches(path, blobs)
    score, verdict = risk(report)
    report["punteggio"], report["verdetto"], report["motivi"] = score, verdict[0], verdict[1:]

    out = out_dir / f"{report['sha256']}.json"
    try:
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        report["report_json"] = str(out)
    except OSError as exc:
        report["report_json"] = f"non salvato: {exc}"
    return report


def print_summary(r: dict) -> None:
    print("=" * 78)
    print(f"{r['file']}  [{r['verdetto']}]  punteggio {r['punteggio']}")
    print(f"sha256 {r['sha256']}")
    print(f"tipo   {r['tipo']}")
    apk = r.get("apk")
    if apk and "errore" not in apk:
        print(f"app    {apk['app_name']} ({apk['package']} v{apk['version']})")
    elif apk:
        print(f"apk    {apk['errore']}")
    for m in r["motivi"]:
        print(f"  - {m}")
    if r["urls"] or r["ips"]:
        print(f"  URL trovati: {len(r['urls'])}, IP trovati: {len(r['ips'])} (dettagli nel JSON)")
    print(f"  report: {r['report_json']}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Triage statico di campioni sospetti (non li esegue)")
    p.add_argument("paths", nargs="+", help="file o cartelle da analizzare")
    p.add_argument("-o", "--out", default="/reports", help="cartella dei report JSON (default /reports)")
    args = p.parse_args(argv)

    out_dir = Path(args.out)
    files: list[Path] = []
    for raw in args.paths:
        path = Path(raw)
        if path.is_dir():
            files += sorted(f for f in path.rglob("*") if f.is_file() and not f.name.startswith("."))
        elif path.is_file():
            files.append(path)
        else:
            print(f"{raw}: non trovato", file=sys.stderr)
    if not files:
        print("Nessun campione da analizzare: copia i file in sandbox/samples/.")
        return 0

    worst = 0
    for f in files:
        r = triage(f, out_dir)
        print_summary(r)
        worst = max(worst, r["punteggio"])
    return 1 if worst >= 4 else 0


if __name__ == "__main__":
    sys.exit(main())
