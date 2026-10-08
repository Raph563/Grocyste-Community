# Reprise

Implémentation de la plateforme approuvée le 3 octobre 2026. Destination :
https://grocyste.banane.fun ; expéditeur grocyste@banane.fun. Le catalogue initial
reste la source publique qualifiée 1.0.0. Aucune donnée métier privée n’est publiée.
Les 70 recettes sont reprises comme fiches ; les préparations et photos sans preuve
de droits restent dans une relecture privée. La production ne sera activée qu’après
qualification du laboratoire et sauvegarde/restauration.

État au 8 octobre 2026 : catalogue accessible en HTTPS sur grocyste.banane.fun.
Production isolée du laboratoire et de Grocy, base PostgreSQL dédiée restaurée
depuis une sauvegarde : 5 098 recettes, 690 produits et deux packs. Les signatures
de tous les éléments des deux téléchargements sont vérifiées (691 et 178 éléments,
dépendances incluses). Les 70 recettes personnelles figurent dans leur pack.

Les 19 tests passent dans le laboratoire PostgreSQL, y compris la concurrence.
Deux tests jusque-là ignorés en SQLite utilisaient une fixture produit sans unité
et un ancien nom de méthode email : fixtures corrigées avant qualification réelle.
Aucun email réel n'a été envoyé pendant ces tests.

Inscriptions et mutations publiques fermées au proxy ; SIGNUPS_OPEN=false.
Le rôle web peut lire les données et écrire seulement les sessions anonymes et
limites de débit. La clé privée de signature et l'invitation du laboratoire ne
sont pas montées dans la production. Les préparations et photos non autorisées
ne sont pas nouvellement publiées. Le site banane.fun reste accessible (HTTP 200).

Les comptes, SMTP dédié, emails reçus, worker de production, appairage et parcours
complet d'import Grocy restent à qualifier avant ouverture communautaire. Cette
mise en ligne n'est pas une livraison complète de la plateforme prévue.

Source et déploiement VPS : /home/wwadmin/grocyste-work/community-20261008.
Sauvegardes privées : production/backups. Le script deploy-public.py rejoue sans
réimporter la base ; aucune information privée de ces dossiers ne va dans Git.
