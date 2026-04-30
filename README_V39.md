# SecurePass V39 - Coffre verrouillé propre

## Nouveautés
- Création obligatoire du mot de passe maître avant utilisation du coffre.
- Coffre verrouillé par défaut.
- Déverrouillage temporaire 10 minutes.
- Le formulaire d’ajout ne demande plus le mot de passe maître.
- Boutons Voir / Masquer pour les mots de passe enregistrés.
- Backend vérifie le mot de passe maître avant ajout ou révélation.

## Lancement
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```
