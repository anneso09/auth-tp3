package com.example.auth_tp3.controller;

import lombok.Data;

/**
 * Représente le JSON envoyé par le client lors du login.
 * Contient tous les éléments du protocole HMAC.
 * Le mot de passe n'est PAS ici — il ne voyage jamais.
 *
 * Exemple JSON reçu :
 * {
 *   "email": "alice@mail.com",
 *   "nonce": "f47ac10b-58cc-4372-a567",
 *   "timestamp": 1712150400,
 *   "hmac": "a3f9bc7d2e..."
 * }
 */
@Data
public class LoginRequest {
    private String email;
    private String nonce;
    private long timestamp;   // long car c'est un nombre epoch en secondes
    private String hmac;
}