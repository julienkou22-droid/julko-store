# JULKO STORE - prêt au déploiement

Boutique client + administration + API Node.js + SQLite.

## URLs une fois déployé
- `/` : boutique
- `/admin/` : administration
- `/health` : contrôle du serveur

## Configuration
Variables nécessaires :
- `JWT_SECRET` : secret long et aléatoire
- `DB_PATH` : chemin de la base SQLite
- `PORT` : fourni par l'hébergeur

Le paiement est actuellement **Wave à la livraison**. Aucune clé Wave n'est nécessaire pour ce mode.

## Avant ouverture publique
1. Déployer le projet sur un hébergement Node/Docker avec disque persistant.
2. Créer le premier administrateur.
3. Remplacer les produits de démonstration par les vrais produits JULKO STORE.
4. Utiliser un domaine HTTPS.
