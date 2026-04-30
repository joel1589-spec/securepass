# SecurePass V43 — Admin sécurisé pro

## Grand admin unique
Un seul compte `super_admin` est autorisé. Au démarrage, si aucun grand admin n'existe, l'application crée :

- username: `admin`
- email: `admin@securepass.local`
- password: `Admin@12345!`

Si plusieurs comptes `super_admin` existent, l'application garde le premier et rétrograde les autres en `user`.

## Console admin
URL :

```text
http://127.0.0.1:5000/securepass-admin-console
```

La console admin a son propre login et n'accepte que le rôle `super_admin`.

## Sécurité
- 2FA obligatoire pour accéder aux données admin.
- Le compte grand admin ne peut pas être suspendu depuis la console.
- Logs des actions admin.
- Vue utilisateurs, paiements, organisations, logs et comptes récents.

## Important
Après la première connexion admin, active la 2FA depuis l'application avant d'utiliser les statistiques admin.
