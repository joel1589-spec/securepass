# SecurePass V37 - Extension navigateur améliorée

Cette version ajoute la détection de mot de passe faible dans le navigateur.

## Fonctionnement extension
- L’utilisateur doit se connecter à l’extension avec son compte SecurePass.
- Free et Basic sont bloqués.
- Pro et Enterprise sont autorisés.
- Si l’utilisateur refuse la génération automatique puis saisit un mot de passe faible, SecurePass propose à nouveau de générer un mot de passe fort.

## Lancement
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## Extension
Dans Chrome/Edge : charger le dossier `browser_extension`.
