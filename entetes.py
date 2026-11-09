"""Analyse des en-têtes de sécurité HTTP d'un site web.

L'outil fait une simple requête (comme un navigateur) et regarde les en-têtes
de la réponse. Il ne teste rien d'autre, il n'attaque pas le site.
"""

# En-têtes de sécurité que je vérifie, avec une explication courte en français.
# L'ordre sert aussi à l'affichage du rapport.
ENTETES_SECURITE = {
    "strict-transport-security": "Force le navigateur à rester en HTTPS (protège contre l'écoute du trafic).",
    "content-security-policy": "Limite d'où viennent scripts et images (protège contre l'injection de code / XSS).",
    "x-frame-options": "Empêche le site d'être affiché dans une iframe (protège contre le clickjacking).",
    "x-content-type-options": "Empêche le navigateur de deviner le type d'un fichier (protège contre certaines attaques).",
    "referrer-policy": "Contrôle les infos envoyées quand on quitte le site (protège la vie privée).",
    "permissions-policy": "Restreint l'accès à la caméra, au micro, à la position, etc.",
}

# En-têtes qui, au contraire, donnent des infos à un attaquant (version du serveur...).
# Leur présence n'est pas une faille, mais vaut mieux les cacher.
ENTETES_BAVARDS = {
    "server": "Révèle le logiciel du serveur (et parfois sa version).",
    "x-powered-by": "Révèle la technologie du site (PHP, Express...).",
    "x-aspnet-version": "Révèle la version d'ASP.NET.",
}


def normaliser(entetes):
    """Met toutes les clés en minuscules pour comparer sans se soucier de la casse."""
    return {cle.lower(): valeur for cle, valeur in entetes.items()}


def analyser(entetes):
    """Analyse un dictionnaire d'en-têtes.

    Renvoie un dictionnaire avec : les en-têtes présents, ceux qui manquent,
    les en-têtes bavards trouvés, le score et la note.
    """
    entetes = normaliser(entetes)

    presents = {}
    manquants = {}
    for cle, description in ENTETES_SECURITE.items():
        if cle in entetes:
            presents[cle] = description
        else:
            manquants[cle] = description

    bavards = {cle: desc for cle, desc in ENTETES_BAVARDS.items() if cle in entetes}

    score = len(presents)
    total = len(ENTETES_SECURITE)

    return {
        "presents": presents,
        "manquants": manquants,
        "bavards": bavards,
        "score": score,
        "total": total,
        "note": note(score, total),
    }


def note(score, total):
    """Donne une note de A à F selon le pourcentage d'en-têtes de sécurité présents."""
    pourcentage = (score / total) * 100 if total else 0
    if pourcentage >= 90:
        return "A"
    if pourcentage >= 70:
        return "B"
    if pourcentage >= 50:
        return "C"
    if pourcentage >= 30:
        return "D"
    if pourcentage > 0:
        return "E"
    return "F"
