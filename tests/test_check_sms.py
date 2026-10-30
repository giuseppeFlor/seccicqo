import unittest
from pathlib import Path

from sms_phishing.check_sms import Sms, analyze, load_messages, parse_content_query

SAMPLE = Path(__file__).resolve().parent.parent / "sms_phishing" / "samples" / "sms_dump_esempio.txt"


class ParseTest(unittest.TestCase):
    def test_parse_multiline_body(self):
        msgs = parse_content_query(SAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(len(msgs), 8)
        poste = next(m for m in msgs if m.id == "104")
        self.assertIn("Non condividerlo", poste.body)
        self.assertEqual(poste.address, "PosteInfo")

    def test_json_input(self):
        tmp = Path(self._testMethodName + ".json")
        tmp.write_text('[{"address": "X", "body": "ciao"}]', encoding="utf-8")
        try:
            self.assertEqual(load_messages(str(tmp))[0].body, "ciao")
        finally:
            tmp.unlink()


class AnalyzeTest(unittest.TestCase):
    def verdict(self, body, sender="+393401234567"):
        return analyze(Sms("1", sender, "0", "1", body)).verdict

    def test_fake_poste(self):
        self.assertEqual(self.verdict("Conto sospeso, verifica: https://poste-verifica.top/x"), "PHISHING PROBABILE")

    def test_ip_link(self):
        self.assertEqual(self.verdict("INPS rimborso: http://10.1.2.3/a"), "PHISHING PROBABILE")

    def test_official_link_ok(self):
        self.assertEqual(self.verdict("Ordine spedito: https://www.amazon.it/gp/x", sender="Amazon"), "ok")

    def test_plain_text_ok(self):
        self.assertEqual(self.verdict("Ciao mamma, arrivo alle 8", sender="Mamma"), "ok")


if __name__ == "__main__":
    unittest.main()
