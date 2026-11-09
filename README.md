# check-entetes

Outil en Python qui analyse les **en-têtes de sécurité HTTP** d'un site web,
met une note de A à F et explique en français ce qui manque.

C'est l'équivalent, en plus simple, de ce que font des services comme
Mozilla Observatory ou securityheaders.com. Je l'ai écrit pour comprendre
concrètement à quoi servent ces en-têtes, parce que les lire une fois ne suffit
pas pour les retenir.

## Ce que fait l'outil

L'outil fait **une seule requête**, comme un navigateur, et lit les en-têtes
que le site renvoie. Il ne teste rien d'autre et n'attaque pas le site.

Il regarde :

- six en-têtes de sécurité recommandés (HSTS, Content-Security-Policy,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) ;
- les en-têtes « bavards » qui révèlent le logiciel du serveur ou la techno du site
  (`Server`, `X-Powered-By`...).

Puis il affiche un rapport avec la note, les en-têtes présents, ceux qui manquent
et pourquoi ils comptent.

## Utilisation

Il faut Python 3.8 ou plus. Aucune librairie à installer, tout vient de la
librairie standard.

```
python check.py exemple.ch
python check.py https://exemple.ch -o rapport.txt
```

Exemple de sortie :

```
Rapport de securite : https://exemple.ch
============================================================
Note : D   (2/6 en-tetes de securite)

En-tetes presents :
  [OK] strict-transport-security
  [OK] x-content-type-options

En-tetes manquants (a ajouter) :
  [!] content-security-policy
      -> Limite d'où viennent scripts et images (protège contre l'injection de code / XSS).
  ...
```

## Tests

```
python -m unittest discover -s tests
```

## Comment c'est organisé

- `reseau.py` : fait la requête et récupère les en-têtes.
- `entetes.py` : analyse les en-têtes et calcule la note (c'est le cœur de l'outil).
- `check.py` : ce qu'on lance ; lit les options et affiche le rapport.
- `tests/` : les tests, qui utilisent de faux en-têtes pour vérifier l'analyse
  sans dépendre d'internet.

## À utiliser de manière responsable

L'outil ne lit que des informations renvoyées publiquement par le site, donc
il est légal à utiliser sur n'importe quel site. Il ne contourne rien et
n'exploite aucune faille.

## Idées pour la suite

- vérifier aussi le contenu des en-têtes, pas seulement leur présence
  (ex : un `max-age` trop court pour HSTS)
- analyser une liste de sites d'un coup
- export du rapport en CSV
Mise à jour contributeurs
Mise à jour contributeurs
