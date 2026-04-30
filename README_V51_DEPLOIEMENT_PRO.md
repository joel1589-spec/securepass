# SecurePass V51 — Render + PostgreSQL + sécurité finale

## 1. Déploiement Render
Build command:
```bash
pip install -r requirements.txt
```
Start command:
```bash
gunicorn wsgi:app
```

## 2. Variables d’environnement obligatoires
Dans Render → Environment:
```env
SECRET_KEY=<Generate>
JWT_SECRET=<Generate>
APP_BASE_URL=https://TON-URL.onrender.com
DATABASE_URL=<Internal Database URL PostgreSQL Render>
FEDAPAY_PUBLIC_KEY=pk_sandbox_...
FEDAPAY_SECRET_KEY=sk_sandbox_...
FEDAPAY_ENV=sandbox
SUPPORT_EMAIL=joelkpeto204@gmail.com
SUPPORT_PHONE=99424087
```

## 3. PostgreSQL Render
Créer une base PostgreSQL dans Render, puis copier l’Internal Database URL dans `DATABASE_URL`.
Le code accepte aussi l’ancien format `postgres://` et le convertit en `postgresql://`.

## 4. FedaPay
En sandbox:
```env
FEDAPAY_ENV=sandbox
```
En production:
```env
FEDAPAY_ENV=live
```
Webhook à mettre dans FedaPay après déploiement:
```text
https://TON-URL.onrender.com/webhook/fedapay
```

## 5. Extension navigateur
Après déploiement, modifier `browser_extension/background.js` et `browser_extension/content.js` pour remplacer localhost par l’URL Render.

## 6. Admin
Compte initial:
```text
admin
Admin@12345!
```
À changer immédiatement après connexion. Active la 2FA admin avant usage réel.

## 7. Important
Ne jamais mettre les clés FedaPay directement dans le code en production.
