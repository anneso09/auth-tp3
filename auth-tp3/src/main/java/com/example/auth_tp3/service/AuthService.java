package com.example.auth_tp3.service;

import com.example.auth_tp3.entity.AuthNonce;
import com.example.auth_tp3.entity.User;
import com.example.auth_tp3.exception.AuthenticationFailedException;
import com.example.auth_tp3.exception.InvalidInputException;
import com.example.auth_tp3.exception.ResourceConflictException;
import com.example.auth_tp3.repository.NonceRepository;
import com.example.auth_tp3.repository.UserRepository;
import org.springframework.stereotype.Service;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

/**
 * Service principal d'authentification.
 * Gère l'inscription et le login avec protocole HMAC.
 *
 * IMPORTANT : TP3 est pédagogique. Le mot de passe est stocké en clair
 * dans MySQL. Ceci sera corrigé dans TP4 avec une Master Key AES-GCM.
 * TP3 améliore le protocole réseau mais pas encore le stockage en base.
 */
@Service  // Dit à Spring que c'est un service — il sera créé automatiquement au démarrage
public class AuthService {

    // Spring injecte automatiquement ces deux repositories
    // C'est ce qu'on appelle l'injection de dépendances
    private final UserRepository userRepository;
    private final NonceRepository nonceRepository;

    public AuthService(UserRepository userRepository, NonceRepository nonceRepository) {
        this.userRepository = userRepository;
        this.nonceRepository = nonceRepository;
    }

    // ===================================
    // INSCRIPTION
    // ===================================

    /**
     * Inscrit un nouvel utilisateur.
     * Le mot de passe est stocké en clair (volontaire pour TP3).
     *
     * @param email    L'email de l'utilisateur
     * @param password Le mot de passe en clair
     * @return L'utilisateur créé
     */
    public User register(String email, String password) {

        // Validation de l'email
        if (email == null || email.isBlank()) {
            throw new InvalidInputException("L'email ne peut pas être vide");
        }
        if (!email.contains("@")) {
            throw new InvalidInputException("Format d'email invalide");
        }

        // Validation du mot de passe — minimum 12 caractères pour TP3
        if (password == null || password.length() < 12) {
            throw new InvalidInputException("Le mot de passe doit faire au moins 12 caractères");
        }

        // Vérifie que l'email n'est pas déjà utilisé
        if (userRepository.existsByEmail(email)) {
            throw new ResourceConflictException("Cet email est déjà utilisé");
        }

        // Crée et sauvegarde l'utilisateur
        User user = new User();
        user.setEmail(email);
        user.setPasswordClear(password);  // Stocké en clair — sera chiffré en TP4

        return userRepository.save(user);  // INSERT INTO users ...
    }

    // ===================================
    // LOGIN — PROTOCOLE HMAC
    // ===================================

    /**
     * Authentifie un utilisateur avec le protocole HMAC.
     * Le mot de passe ne circule jamais sur le réseau.
     *
     * @param email     Email de l'utilisateur
     * @param nonce     UUID unique généré par le client
     * @param timestamp Horodatage epoch en secondes
     * @param hmac      Signature HMAC calculée par le client
     * @return Un token d'accès si l'authentification réussit
     */
    public String login(String email, String nonce, long timestamp, String hmac) {

        // VÉRIFICATION 1 : l'email existe-t-il en base ?
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationFailedException("Authentification échouée"));
        // Note : on dit "Authentification échouée" et pas "Email inconnu"
        // pour ne pas donner d'indices à un attaquant

        // VÉRIFICATION 2 : le timestamp est-il dans la fenêtre de ±60 secondes ?
        long currentTime = System.currentTimeMillis() / 1000;  // Heure actuelle en secondes
        if (Math.abs(currentTime - timestamp) > 60) {
            throw new AuthenticationFailedException("Authentification échouée");
        }

        // VÉRIFICATION 3 : le nonce a-t-il déjà été utilisé ?
        Optional<AuthNonce> existingNonce = nonceRepository.findByUserAndNonce(user, nonce);
        if (existingNonce.isPresent()) {
            throw new AuthenticationFailedException("Authentification échouée");
        }

        // VÉRIFICATION 4 : le HMAC est-il valide ?
        // On reconstruit le message exactement comme le client l'a fait
        String message = email + ":" + nonce + ":" + timestamp;

        // On recalcule le HMAC avec le mot de passe stocké en base
        String expectedHmac = calculateHmac(user.getPasswordClear(), message);

        // Comparaison en temps constant — empêche les attaques timing
        if (!MessageDigest.isEqual(
                expectedHmac.getBytes(StandardCharsets.UTF_8),
                hmac.getBytes(StandardCharsets.UTF_8))) {
            throw new AuthenticationFailedException("Authentification échouée");
        }

        // SUCCÈS — on consomme le nonce pour empêcher le rejeu
        AuthNonce usedNonce = new AuthNonce();
        usedNonce.setUser(user);
        usedNonce.setNonce(nonce);
        usedNonce.setExpiresAt(LocalDateTime.now().plusMinutes(2));
        usedNonce.setConsumed(true);
        nonceRepository.save(usedNonce);  // INSERT INTO auth_nonce ...

        // Génère et retourne un token d'accès simple (UUID)
        // En production on utiliserait JWT — ici on simplifie
        return UUID.randomUUID().toString();
    }

    // ===================================
    // MÉTHODE PRIVÉE — CALCUL HMAC
    // ===================================

    /**
     * Calcule une signature HMAC-SHA256.
     * C'est la fonction mathématique à sens unique qui mélange
     * la clé secrète (mot de passe) avec le message.
     *
     * @param key     La clé secrète = le mot de passe de l'utilisateur
     * @param message Le message à signer = email:nonce:timestamp
     * @return La signature en hexadécimal
     */
    private String calculateHmac(String key, String message) {
        try {
            // On dit à Java qu'on veut utiliser l'algorithme HMAC-SHA256
            Mac mac = Mac.getInstance("HmacSHA256");

            // On configure la clé secrète
            SecretKeySpec secretKey = new SecretKeySpec(
                    key.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
            );
            mac.init(secretKey);

            // On calcule la signature et on la convertit en hexadécimal
            byte[] hmacBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hmacBytes);

        } catch (Exception e) {
            throw new RuntimeException("Erreur lors du calcul HMAC", e);
        }
    }
}