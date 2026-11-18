# JULKO STORE - version consolidée

Variables Railway requises:
- JWT_SECRET
- ADMIN_SETUP_TOKEN
- DB_PATH=/data/julko-store.db

Le volume Railway doit être monté sur `/data`.

Pages:
- `/` boutique
- `/admin` administration
- `/setup-admin` création unique du premier administrateur
- `/health` contrôle du serveur

Fonctions testées:
- inscription et connexion client/admin
- catalogue initial en base
- ajout/modification/masquage de produits
- panier et commande
- stock décrémenté côté serveur
- suivi client
- validation/annulation et livraison
- paiement Wave à la livraison
- WhatsApp service client + récapitulatif panier
- migration d'une ancienne base
