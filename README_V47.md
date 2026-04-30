# SecurePass V47

Corrections :
- intégration navigateur autorisée pour les employés Enterprise si l'organisation est active ;
- affichage utilisateur corrigé : uniquement le username, plus de `@ •` ;
- champs sensibles vidés et anti-autofill renforcé ;
- cache forcé en v47.

Lancement :
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```
