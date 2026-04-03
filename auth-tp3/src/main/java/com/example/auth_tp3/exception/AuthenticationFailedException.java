package com.example.auth_tp3.exception;

/**
 * Exception lancée quand l'authentification échoue.
 * Ex: mauvais mot de passe, HMAC invalide, nonce expiré.
 * Correspond au code HTTP 401 (Unauthorized).
 */
public class AuthenticationFailedException extends RuntimeException {

    public AuthenticationFailedException(String message) {
        super(message);
    }
}