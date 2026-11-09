"""Récupération des en-têtes HTTP d'un site (séparé du reste pour pouvoir le tester)."""

import urllib.error
import urllib.request

# Certains sites renvoient une erreur ou une page différente si le User-Agent est vide.
ENTETE_REQUETE = {"User-Agent": "check-entetes/1.0 (analyse de securite)"}


def corriger_url(url):
    """Ajoute https:// devant l'adresse si l'utilisateur ne l'a pas mis."""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def recuperer_entetes(url, timeout=10):
    """Fait la requête et renvoie (url_finale, dict des en-têtes).

    Lève une exception si le site est injoignable, pour que l'appelant l'affiche.
    """
    url = corriger_url(url)
    requete = urllib.request.Request(url, headers=ENTETE_REQUETE, method="GET")
    with urllib.request.urlopen(requete, timeout=timeout) as reponse:
        # reponse.url change si le site a redirigé (ex: http -> https)
        return reponse.url, dict(reponse.headers)
