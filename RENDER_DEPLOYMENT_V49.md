# SecurePass V49 - Déploiement Render sans domaine personnalisé

## 1. Web Service Render
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn wsgi:app`

## 2. Variables d'environnement Render
Ajoute dans Render → Environment :

```env
SECRET_KEY=<python -c "import secrets; print(secrets.token_hex(32))">
JWT_SECRET=<python -c "import secrets; print(secrets.token_hex(32))">
APP_BASE_URL=https://NOM-DE-TON-APP.onrender.com
SUPPORT_EMAIL=joelkpeto204@gmail.com
SUPPORT_PHONE=99424087
FEDAPAY_ENVIRONMENT=sandbox
FEDAPAY_PUBLIC_KEY=pk_sandbox_xxxxx
FEDAPAY_SECRET_KEY=sk_sandbox_xxxxx
FEDAPAY_WEBHOOK_SECRET=ton_secret_webhook_si_disponible
```

## 3. Base de données
Pour tester vite, SQLite fonctionne. Pour vendre réellement, ajoute Render PostgreSQL et connecte-le au service. Render fournit `DATABASE_URL` automatiquement.

## 4. FedaPay
Dans FedaPay sandbox :
- Callback / return URL: `https://NOM-DE-TON-APP.onrender.com/fedapay/return`
- Webhook URL: `https://NOM-DE-TON-APP.onrender.com/webhook/fedapay`

## 5. Extension navigateur
Dans `browser_extension`, remplace l'API locale par `https://NOM-DE-TON-APP.onrender.com`, puis recharge l’extension.

## 6. Avant production réelle
- Régénère les clés FedaPay exposées.
- Mets `FEDAPAY_ENVIRONMENT=live`.
- Utilise clés live.
- Utilise PostgreSQL.
