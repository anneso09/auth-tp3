package com.example.auth_tp3.exception;

/**
 * Exception lancée quand une ressource existe déjà.
 * Ex: tentative d'inscription avec un email déjà utilisé.
 * Correspond au code HTTP 409 (Conflict).
 */
public class ResourceConflictException extends RuntimeException {

    public ResourceConflictException(String message) {
        super(message);
    }
}