package com.example.auth_tp3.controller;

import lombok.Data;

/**
 * Représente le JSON envoyé par le client lors de l'inscription.
 * Le client envoie exactement ces deux champs dans le body de la requête.
 *
 * Exemple JSON reçu :
 * {
 *   "email": "alice@mail.com",
 *   "password": "MonMotDePasse123!"
 * }
 */
@Data  // Lombok génère getters et setters automatiquement
public class RegisterRequest {
    private String email;
    private String password;
}