"""Vérificateur d'en-têtes de sécurité HTTP.

Exemples :
    python check.py exemple.ch
    python check.py https://exemple.ch -o rapport.txt
"""

import argparse
import sys
import urllib.error

import entetes
import reseau


def construire_rapport(url_finale, resultat):
    """Construit le texte du rapport (liste de lignes)."""
    lignes = []
    lignes.append(f"Rapport de securite : {url_finale}")
    lignes.append("=" * 60)
    lignes.append(f"Note : {resultat['note']}   ({resultat['score']}/{resultat['total']} en-tetes de securite)")
    lignes.append("")

    lignes.append("En-tetes presents :")
    if resultat["presents"]:
        for cle in resultat["presents"]:
            lignes.append(f"  [OK] {cle}")
    else:
        lignes.append("  (aucun)")
    lignes.append("")

    lignes.append("En-tetes manquants (a ajouter) :")
    if resultat["manquants"]:
        for cle, desc in resultat["manquants"].items():
            lignes.append(f"  [!] {cle}")
            lignes.append(f"      -> {desc}")
    else:
        lignes.append("  (aucun, tres bien)")
    lignes.append("")

    if resultat["bavards"]:
        lignes.append("En-tetes qui donnent trop d'infos :")
        for cle, desc in resultat["bavards"].items():
            lignes.append(f"  [i] {cle} : {desc}")
        lignes.append("")

    return lignes


def main():
    parser = argparse.ArgumentParser(description="Analyse les en-tetes de securite HTTP d'un site.")
    parser.add_argument("url", help="adresse du site, ex: exemple.ch")
    parser.add_argument("-o", "--sortie", help="enregistrer le rapport dans un fichier")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="delai d'attente en secondes")
    args = parser.parse_args()

    try:
        url_finale, brut = reseau.recuperer_entetes(args.url, timeout=args.timeout)
    except (urllib.error.URLError, OSError) as erreur:
        print(f"Impossible de joindre le site : {erreur}", file=sys.stderr)
        sys.exit(1)

    resultat = entetes.analyser(brut)
    lignes = construire_rapport(url_finale, resultat)

    texte = "\n".join(lignes)
    print(texte)

    if args.sortie:
        with open(args.sortie, "w", encoding="utf-8") as f:
            f.write(texte + "\n")
        print(f"\nRapport enregistre : {args.sortie}")


if __name__ == "__main__":
    main()
