import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check
import entetes
import reseau


class TestAnalyse(unittest.TestCase):

    def test_site_bien_securise(self):
        brut = {
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        resultat = entetes.analyser(brut)
        self.assertEqual(resultat["score"], 6)
        self.assertEqual(resultat["note"], "A")
        self.assertEqual(resultat["manquants"], {})

    def test_site_sans_rien(self):
        resultat = entetes.analyser({"Content-Type": "text/html"})
        self.assertEqual(resultat["score"], 0)
        self.assertEqual(resultat["note"], "F")
        self.assertEqual(len(resultat["manquants"]), 6)

    def test_casse_ignoree(self):
        # le serveur peut écrire l'en-tête comme il veut, on doit le reconnaître quand même
        resultat = entetes.analyser({"x-frame-options": "DENY"})
        self.assertIn("x-frame-options", resultat["presents"])

    def test_entetes_bavards(self):
        resultat = entetes.analyser({"Server": "Apache/2.4.1", "X-Powered-By": "PHP/7.4"})
        self.assertIn("server", resultat["bavards"])
        self.assertIn("x-powered-by", resultat["bavards"])


class TestNote(unittest.TestCase):

    def test_bornes(self):
        self.assertEqual(entetes.note(6, 6), "A")
        self.assertEqual(entetes.note(3, 6), "C")
        self.assertEqual(entetes.note(0, 6), "F")


class TestUrl(unittest.TestCase):

    def test_ajoute_https(self):
        self.assertEqual(reseau.corriger_url("exemple.ch"), "https://exemple.ch")

    def test_garde_http_existant(self):
        self.assertEqual(reseau.corriger_url("http://exemple.ch"), "http://exemple.ch")


class TestRapport(unittest.TestCase):

    def test_contient_note_et_url(self):
        resultat = entetes.analyser({"X-Frame-Options": "DENY"})
        lignes = check.construire_rapport("https://exemple.ch", resultat)
        texte = "\n".join(lignes)
        self.assertIn("https://exemple.ch", texte)
        self.assertIn("Note :", texte)


if __name__ == "__main__":
    unittest.main()
