package com.example.auth_tp3.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Gestionnaire global des exceptions.
 * Intercepte toutes les exceptions de l'application et
 * renvoie une réponse JSON cohérente au lieu d'une erreur Java incompréhensible.
 */
@RestControllerAdvice  // Dit à Spring : surveille toutes les exceptions de tous les controllers
public class GlobalExceptionHandler {

    /**
     * Construit la réponse JSON d'erreur.
     * Toutes les erreurs auront exactement le même format.
     */
    private Map<String, Object> buildError(HttpStatus status, String message, HttpServletRequest request) {
        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now().toString());  // Quand l'erreur s'est produite
        error.put("status", status.value());                     // Le code HTTP (400, 401, 409...)
        error.put("error", status.getReasonPhrase());            // Le texte du code ("Bad Request"...)
        error.put("message", message);                           // Notre message personnalisé
        error.put("path", request.getRequestURI());              // L'URL qui a causé l'erreur
        return error;
    }

    // Intercepte InvalidInputException → renvoie 400
    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidInput(
            InvalidInputException ex, HttpServletRequest request) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)  // 400
                .body(buildError(HttpStatus.BAD_REQUEST, ex.getMessage(), request));
    }

    // Intercepte AuthenticationFailedException → renvoie 401
    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<Map<String, Object>> handleAuthFailed(
            AuthenticationFailedException ex, HttpServletRequest request) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)  // 401
                .body(buildError(HttpStatus.UNAUTHORIZED, ex.getMessage(), request));
    }

    // Intercepte ResourceConflictException → renvoie 409
    @ExceptionHandler(ResourceConflictException.class)
    public ResponseEntity<Map<String, Object>> handleConflict(
            ResourceConflictException ex, HttpServletRequest request) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)  // 409
                .body(buildError(HttpStatus.CONFLICT, ex.getMessage(), request));
    }
}