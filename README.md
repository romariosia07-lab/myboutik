# MYBOUTIK

Plateforme multi-boutiques : plusieurs personnes créent chacune leur boutique
en ligne (catalogue, vitrine publique, commandes en paiement à la livraison),
avec un tableau de bord complet (commandes, livraisons, clients, finances,
analytique, marketing).

Voir le plan de construction complet dans la conversation Claude Code qui a
généré ce projet pour le contexte et les décisions prises (nom, périmètre,
URLs). Résumé rapide ci-dessous.

## Architecture

- **Backend** : `index.php` (PHP + PostgreSQL), mono-fichier, routeur
  `module`/`action` (même style que ROM_MONEY). Aucun secret codé en dur :
  tout passe par des variables d'environnement.
- **Frontend** : 3 pages HTML/JS statiques, sans build :
  - `index.html` — page marketing + inscription/connexion.
  - `dashboard/index.html` — tableau de bord (multi-boutiques + gestion).
  - `store/index.html` — vitrine publique d'une boutique + commande COD.
  - `config.js` — un seul endroit pour pointer vers l'URL du backend deployé.

Le frontend et le backend sont pensés pour être déployés **séparément** (le
frontend sur un hébergeur statique, le backend sur un hébergeur PHP), comme
c'est déjà le cas pour ROM_MONEY.

## 1. Déployer le backend (PHP + PostgreSQL)

Render et Neon ne sont pas concurrents : **Render** héberge le code PHP
(`index.php`) ; **Neon** ne fait que la base PostgreSQL. Vous pouvez très
bien exécuter le PHP sur Render tout en pointant vers une base Neon —
c'est même recommandé ici, car le PostgreSQL gratuit de Render expire au
bout d'un moment alors que le tier gratuit de Neon est plus pérenne (et
vous en avez déjà un pour Gestion Entreprise — créez simplement un
**nouveau projet/base séparé** pour MYBOUTIK, ne réutilisez pas la même
base).

1. Créez la base : sur [neon.tech](https://neon.tech), *New Project* →
   notez les identifiants de connexion (host, database, user, password,
   port — Neon les affiche aussi sous forme d'une seule "connection
   string", que vous pouvez éclater vous-même en `DB_HOST`/`DB_NAME`/etc.).
   Vous pouvez aussi utiliser Render Postgres ou Supabase à la place — le
   backend ne fait aucune hypothèse sur le fournisseur, seuls les
   identifiants `DB_*` changent.
2. Déployez ce dossier comme un service web PHP sur Render. `Procfile` contient déjà la
   commande de démarrage (`php -S 0.0.0.0:$PORT router.php`) ; si votre
   hébergeur utilise Apache à la place, le `.htaccess` fourni fait le même
   travail (réécriture de toutes les requêtes vers `index.php`).
3. Configurez ces variables d'environnement sur le service :
   - `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`, `DB_PORT` — connexion PostgreSQL.
   - `DB_SSLMODE=require` — **nécessaire avec Neon** (et sans danger avec
     Render Postgres/un Postgres local, donc à mettre systématiquement si
     vous utilisez Neon). Laissez cette variable absente pour un Postgres
     local sans SSL configuré.
   - `JWT_SECRET` — chaîne aléatoire longue (ex: générée avec `openssl rand -hex 32`). **Obligatoire**, l'app refuse de démarrer sans.
   - `INSTALL_KEY` — optionnel, sinon `JWT_SECRET` est réutilisée pour protéger `/install`.
   - `APP_ENV` — laissez absent ou mettez `production` en ligne. Ne mettez `development` qu'en local.
4. Une fois déployé, initialisez les tables en visitant :
   `https://votre-backend.example.com/install?key=VOTRE_INSTALL_KEY`
   (à refaire après chaque ajout de table dans une future mise à jour — c'est
   sans danger, toutes les créations sont `IF NOT EXISTS`).
5. Ouvrez `index.php` et complétez le tableau `$ALLOWED_ORIGINS` avec le(s)
   domaine(s) où sera hébergé le frontend (sinon les navigateurs bloqueront
   les appels API depuis le site).

## 2. Déployer le frontend (statique)

Hébergez le dossier racine (moins `index.php`, qui reste côté backend — vous
pouvez aussi tout héberger ensemble si votre hébergeur PHP sert aussi les
fichiers statiques, auquel cas ignorez cette section et servez tout depuis le
même service) sur GitHub Pages, Netlify, Vercel ou équivalent.

Modifiez **`config.js`** :
```js
window.MYBOUTIK_API_URL = 'https://votre-backend.example.com';
```

### URLs "jolies" pour les boutiques (`/store/{slug}`)

Par défaut, la vitrine fonctionne partout avec `store/index.html?b={slug}`
(aucune configuration serveur nécessaire). Pour activer l'URL plus courte
`/store/{slug}` :
- **Netlify** : ajoutez un fichier `_redirects` à la racine avec
  `/store/*  /store/index.html  200`.
- **Apache** : le `.htaccess` fourni est pour le backend PHP ; si le
  frontend est servi par Apache aussi, ajoutez une règle similaire dans son
  propre `.htaccess`.
- **GitHub Pages** : utilisez la redirection `?b=` (GitHub Pages ne supporte
  pas nativement les rewrites), ou passez à Netlify/Vercel pour ce besoin.

Le plan prévoyait aussi une bascule future vers un sous-domaine par boutique
(`{slug}.monsite.com`) : le `slug` de la boutique est déjà l'identifiant
public dans les deux cas, donc aucun changement de modèle de données ne sera
nécessaire le jour où vous configurez le DNS wildcard.

## 3. Envoi réel de l'email de vérification

Non branché dans cette version : `auth_register()` (dans `index.php`)
journalise le lien de vérification côté serveur (`error_log`) au lieu de
l'envoyer par email. Pour l'activer :
1. Choisissez un fournisseur transactionnel (Brevo, SendGrid, Resend…) ou un
   compte SMTP.
2. Dans `auth_register()`, remplacez le `error_log(...)` par un appel à
   l'API de ce fournisseur (ou `PHPMailer` pour du SMTP classique).

En attendant, en local (`APP_ENV=development`), la réponse de
`/auth?action=register` renvoie directement `verify_link_dev_only` — la page
`index.html` l'affiche pour pouvoir tester le parcours complet sans email.

## 4. Tester en local

```
php -S localhost:8000 router.php
```
(nécessite une base PostgreSQL accessible en local ou une base de dev
distante référencée dans les variables d'environnement — `APP_ENV`,
`DB_HOST`, etc. peuvent être passées via un fichier `.env` chargé par votre
shell, ou directement en variables d'environnement système.)

Puis ouvrez `index.html` dans un navigateur (avec `config.js` pointant sur
`http://localhost:8000`), créez un compte, récupérez le lien de vérification
dans le message de la page (mode développement) ou dans les logs du serveur
PHP, connectez-vous, créez une boutique, ajoutez un produit, ouvrez
`store/index.html?b=votre-slug` dans un autre onglet et passez une commande
en paiement à la livraison.

## Hors périmètre de cette version (voir le plan initial)

- Clonage de boutique par IA depuis une URL, génération de fiche produit par IA.
- Paiement en ligne / mobile money (paiement à la livraison uniquement).
- Multi-devise / multi-pays (XOF fixe pour l'instant).
- PWA (manifest/icônes/service worker) — pas encore ajouté, contrairement
  aux autres modules de cet environnement (ROM_MONEY, ROM_BUSINESS,
  ROM_GUICHET) qui en ont un.
