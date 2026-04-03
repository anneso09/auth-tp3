# TP3 - Serveur d'Authentification Forte (HMAC)

## Description
API REST sécurisée avec protocole d'authentification HMAC-SHA256.
Le mot de passe ne circule jamais sur le réseau.

## Prérequis
- Java 17
- MySQL via WAMP (port 3306)
- Maven

## Lancer MySQL
1. Démarrer WAMP
2. Vérifier que MySQL tourne sur le port 3306
3. La base `auth_tp3` doit exister avec les tables `users` et `auth_nonce`

## Configurer application.properties
```
spring.datasource.url=jdbc:mysql://localhost:3306/auth_tp3
spring.datasource.username=root
spring.datasource.password=
```

## Lancer l'API
```bash
.\mvnw spring-boot:run
```
L'API démarre sur http://localhost:8080

## Lancer le client Java
```bash
cd client
.\mvnw javafx:run
```

## Compte de test
- Email : toto@example.com
- Password : MonMotDePasse123!

## Endpoints
| Méthode | URL | Description |
|---------|-----|-------------|
| POST | /api/auth/register | Inscription |
| POST | /api/auth/login | Login HMAC |
| GET | /api/me | Route protégée |

## Protocole HMAC (Login)
1. Client génère nonce (UUID) + timestamp
2. Client calcule : `hmac = HMAC_SHA256(pwd, email:nonce:timestamp)`
3. Client envoie : email + nonce + timestamp + hmac (jamais le pwd)
4. Serveur recalcule le HMAC et compare en temps constant
5. Serveur vérifie timestamp (±60s) et nonce (usage unique)

## Analyse de sécurité TP3

### Points forts
- Mot de passe jamais envoyé sur le réseau
- Nonce usage unique — empêche le rejeu
- Timestamp ±60s — limite la durée d'attaque
- Comparaison en temps constant — empêche les attaques timing

### Limite principale
Le mot de passe est stocké EN CLAIR dans MySQL.
Si la base de données est volée, tous les mots de passe sont visibles.
Ce sera corrigé dans TP4 avec un chiffrement AES-GCM via Master Key.

## Qualité
- 15 tests JUnit
- Analyse SonarCloud connectée
- Couverture : 80%+