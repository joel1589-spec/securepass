# SecurePass V48 Production Launch Ready

Contact support intégré :
- Téléphone : 99424087
- Email : joelkpeto204@gmail.com

Inclus :
- FedaPay seul pour les paiements
- Plans Free / Basic / Pro / Enterprise
- Quotas serveur par plan
- 2FA obligatoire
- Coffre chiffré avec mot de passe maître
- Extension navigateur Pro / Enterprise
- Enterprise avec employés et avantages Pro
- Console super_admin séparée, 1 seul super_admin maximum
- Annulation abonnement
- Factures PDF avec contact support
- Fichiers production : wsgi.py, Procfile, Gunicorn

Lancement local :

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Admin local par défaut :
- username : admin
- password : Admin@12345!

Avant production : régénérer les clés FedaPay, remplacer les secrets, mettre APP_BASE_URL en HTTPS, configurer le webhook FedaPay, publier l’extension avec l’URL du domaine.
