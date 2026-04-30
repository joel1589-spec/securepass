# SecurePass V52 — Version complète

Cette version reprend la V51 complète avec les corrections V52 :

- QR 2FA corrigé et compatible Google Authenticator / Microsoft Authenticator.
- Le secret TOTP n'est plus régénéré à chaque affichage du QR.
- Vérification 2FA avec `valid_window=1` pour éviter les erreurs de décalage d'heure.
- Cache frontend forcé en `v=52`.
- Placeholders propres : `nom`, `exemple@gmail.com`.
- Compatible Render : `Procfile`, `wsgi.py`, `render.yaml`, `.env.example`.

## Déploiement Render

Build command :

```bash
pip install -r requirements.txt
```

Start command :

```bash
gunicorn wsgi:app
```

Variables Render minimales :

```env
SECRET_KEY=une_cle_longue_et_secrete
JWT_SECRET=une_autre_cle_longue_et_secrete
FEDAPAY_PUBLIC_KEY=pk_sandbox_xxx
FEDAPAY_SECRET_KEY=sk_sandbox_xxx
FEDAPAY_ENV=sandbox
APP_BASE_URL=https://ton-service.onrender.com
SUPPORT_EMAIL=joelkpeto204@gmail.com
SUPPORT_PHONE=99424087
```

Après remplacement du code :

```bash
git add .
git commit -m "Upgrade SecurePass V52 complete"
git push
```
