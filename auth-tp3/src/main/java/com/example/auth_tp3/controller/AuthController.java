package com.example.auth_tp3.controller;

import com.example.auth_tp3.entity.User;
import com.example.auth_tp3.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller REST principal — gère les endpoints d'authentification.
 * C'est la porte d'entrée de l'API. Il reçoit les requêtes HTTP,
 * délègue le travail au AuthService, et renvoie les réponses JSON.
 *
 * Endpoints disponibles :
 * POST /api/auth/register → inscription
 * POST /api/auth/login    → connexion avec protocole HMAC
 * GET  /api/me            → route protégée
 */
@RestController          // Dit à Spring que cette classe gère des requêtes HTTP et renvoie du JSON
@RequestMapping("/api")  // Toutes les routes de ce controller commencent par /api
public class AuthController {

    // Spring injecte automatiquement le service
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // ===================================
    // INSCRIPTION
    // POST /api/auth/register
    // ===================================

    /**
     * Endpoint d'inscription.
     * Reçoit email + password, crée l'utilisateur en base.
     *
     * @param request Le JSON envoyé par le client
     * @return 201 Created si succès, 400/409 si erreur
     */
    @PostMapping("/auth/register")  // Écoute les POST sur /api/auth/register
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
        // @RequestBody = Spring lit le JSON reçu et le convertit en objet RegisterRequest

        User user = authService.register(request.getEmail(), request.getPassword());

        // Construit la réponse JSON de succès
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Inscription réussie");
        response.put("email", user.getEmail());

        // 201 Created = ressource créée avec succès
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ===================================
    // LOGIN
    // POST /api/auth/login
    // ===================================

    /**
     * Endpoint de connexion avec protocole HMAC.
     * Reçoit email + nonce + timestamp + hmac.
     * Le mot de passe ne circule JAMAIS.
     *
     * @param request Le JSON envoyé par le client
     * @return 200 OK + accessToken si succès, 401 si échec
     */
    @PostMapping("/auth/login")  // Écoute les POST sur /api/auth/login
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {

        String token = authService.login(
                request.getEmail(),
                request.getNonce(),
                request.getTimestamp(),
                request.getHmac()
        );

        // Construit la réponse avec le token
        Map<String, Object> response = new HashMap<>();
        response.put("accessToken", token);
        response.put("expiresAt", System.currentTimeMillis() + (15 * 60 * 1000)); // +15 minutes

        return ResponseEntity.ok(response);  // 200 OK
    }

    // ===================================
    // ROUTE PROTÉGÉE
    // GET /api/me
    // ===================================

    /**
     * Route protégée — accessible uniquement avec un token valide.
     * Pour TP3, on vérifie juste que le header Authorization est présent.
     *
     * @param authHeader Le header "Authorization: Bearer <token>"
     * @return 200 OK si token présent, 401 sinon
     */
    @GetMapping("/me")  // Écoute les GET sur /api/me
    public ResponseEntity<Map<String, Object>> getMe(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        // @RequestHeader = lit le header HTTP de la requête
        // required = false = pas d'erreur automatique si absent, on gère nous-mêmes

        // Vérifie que le header Authorization est présent et commence par "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            Map<String, Object> error = new HashMap<>();
            error.put("message", "Token manquant ou invalide");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }

        // Extrait le token (enlève "Bearer " du début)
        String token = authHeader.substring(7);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Accès autorisé");
        response.put("token", token);

        return ResponseEntity.ok(response);
    }
}