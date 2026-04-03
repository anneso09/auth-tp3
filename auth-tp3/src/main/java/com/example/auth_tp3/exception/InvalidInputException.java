package com.example.auth_tp3.exception;

/**
 * Exception lancée quand les données envoyées par le client sont invalides.
 * Ex: email vide, mot de passe trop court, format incorrect.
 * Correspond au code HTTP 400 (Bad Request).
 */
public class InvalidInputException extends RuntimeException {

    // RuntimeException = une erreur qui peut arriver n'importe quand
    // On passe juste un message qui explique le problème
    public InvalidInputException(String message) {
        super(message);
    }
}