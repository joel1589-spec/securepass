# SecurePass V38

Nouveautés :
- Les employés créés par un admin Enterprise ne voient plus l’onglet Abonnement.
- Les employés Enterprise bénéficient des avantages Pro : extension navigateur, coffre, API/audit selon règles Pro.
- Extension navigateur : sauvegarde automatiquement dans le coffre les comptes créés sur les sites.
- Audit sécurité du coffre avec explications simples : force des mots de passe, réutilisation, activité SecurePass.
- Boutons Voir / Masquer corrigés.

Lancement :
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Extension : supprimer l’ancienne extension puis recharger `browser_extension/`.
