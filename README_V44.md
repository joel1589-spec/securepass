# SecurePass V44 - Désabonnement propre

Ajouts :
- Bouton **Annuler mon abonnement** pour Basic / Pro / Enterprise.
- Retour immédiat au plan Free après annulation.
- Désactivation de l’intégration navigateur après annulation.
- Employés Enterprise : pas d’annulation possible, abonnement géré par l’admin entreprise.
- Si un admin Enterprise annule, l’organisation est désactivée et les employés perdent les avantages Pro.
- Historique de paiement conserve une entrée `cancelled`.

Lancement :
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```
