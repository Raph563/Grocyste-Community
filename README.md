# Grocyste Communauté

Catalogue public de recettes, produits et packs, avec sources, licences et
références versionnées : **https://grocyste.banane.fun**.

État vérifié au 8 octobre 2026 : consultation, recherche, filtres, fiches détaillées
et téléchargements signés. Le catalogue contient 5 098 recettes, 690 produits,
un pack des 70 recettes personnelles et un pack produits. Les téléchargements
incluent leurs dépendances. Les données de stock et achats restent privées.

**Les inscriptions et contributions publiques sont fermées.** Les comptes,
la modération, la file email et l'association Grocy sont implémentés, mais leur
parcours de production complet n'est pas encore qualifié. Aucun fonctionnement
réel de SMTP ou import communautaire dans Grocy n'est annoncé ici.

## Architecture et validation

Python 3.12 / Flask, PostgreSQL 17 et interface JavaScript ES modules construite
avec Node 24. Les images Docker utilisent des dépendances et images de base
verrouillées. Le service tourne sans root, sans socket Docker, avec un système
de fichiers en lecture seule. La production ne reçoit aucune clé ni base Grocy.

Les données approuvées sont signées Ed25519. Le code est sous GPL v3 ou ultérieure ;
les contenus conservent leurs licences et attributions propres. Les préparations
ou photos dont les droits restent inconnus ne sont pas nouvellement publiées.

Les 19 tests passent sur PostgreSQL en laboratoire. Les tests de transport email
utilisent un transport simulé. Les sauvegardes ont été restaurées dans la base
de production isolée et leurs volumes vérifiés ; les signatures des deux packs
ont été vérifiées depuis l'URL publique.

## Installation

Construire l'image avec `docker build --target runtime -t grocyste-community .`.
Le stage `tests` exécute les tests ; pour qualifier la concurrence, fournir
`TEST_DATABASE_URL_FILE` pointant vers une base PostgreSQL **de laboratoire**.
Les tests créent et suppriment leurs schémas isolés.

Les commandes opérateur `python -m community.cli keys`, `init` et `seed`
préparent les clés, le schéma, l'invitation privée et le catalogue signé. Lire
leur aide avant installation. Aucun secret n'est fourni dans ce dépôt.

Le runtime lit `DATABASE_URL_FILE`, `SEAL_KEY_FILE`, `DATA_PUBLIC_KEY_FILE`,
`STATE_DIR`, `PUBLIC_ORIGIN` et `SIGNUPS_OPEN`. Ne pas monter la clé privée de
signature dans le processus public. Garder `SIGNUPS_OPEN=false` jusqu'à la
qualification réelle des emails, droits et imports. Le déploiement public actuel
refuse également les mutations au proxy et utilise un rôle SQL limité au
catalogue, sessions anonymes et limiteurs de débit.

Voir [HANDOFF](HANDOFF.md) et [TASKTODO](TASKTODO.md) pour les limites de couverture
et le travail restant avant une livraison communautaire complète.
