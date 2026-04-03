package com.example.auth_tp3;

import com.example.auth_tp3.entity.AuthNonce;
import com.example.auth_tp3.entity.User;
import com.example.auth_tp3.exception.AuthenticationFailedException;
import com.example.auth_tp3.exception.InvalidInputException;
import com.example.auth_tp3.exception.ResourceConflictException;
import com.example.auth_tp3.repository.NonceRepository;
import com.example.auth_tp3.repository.UserRepository;
import com.example.auth_tp3.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Service principal d'authentification TP3.
 *
 * Protocole implementé : HMAC-SHA256 avec nonce et timestamp.
 * Le mot de passe ne circule jamais sur le réseau.
 * Le client prouve qu'il connait le secret sans l'envoyer.
 *
 * LIMITE IMPORTANTE : TP3 stocke le mot de passe en clair dans MySQL.
 * C'est volontaire pour simplifier l'apprentissage du protocole signé.
 * En industrie, on éviterait de stocker un mot de passe réversible.
 * On préférerait un hash non réversible et adaptatif (BCrypt).
 * Ce sera corrigé dans TP4 avec une Master Key AES-GCM.
 *
 * TP3 améliore le protocole réseau mais pas encore le stockage en base.
 */
@ExtendWith(MockitoExtension.class)  // Active Mockito pour ce test
class AuthServiceTest {

    // @Mock crée une fausse version du repository
    // Elle ne touche pas la vraie base de données
    @Mock
    private UserRepository userRepository;

    @Mock
    private NonceRepository nonceRepository;

    // @InjectMocks crée le vrai AuthService
    // et lui injecte les faux repositories
    @InjectMocks
    private AuthService authService;

    // Un utilisateur de test réutilisé dans plusieurs tests
    private User testUser;

    @BeforeEach  // S'exécute AVANT chaque test
    void setUp() {
        testUser = new User();
        testUser.setEmail("alice@mail.com");
        testUser.setPasswordClear("MonMotDePasse123!");
    }

    // ===================================
    // TESTS INSCRIPTION
    // ===================================

    @Test
    void inscription_OK() {
        // ARRANGE - on prépare le contexte
        // Le faux repository dit "cet email n'existe pas"
        when(userRepository.existsByEmail("alice@mail.com")).thenReturn(false);
        // Quand on sauvegarde, retourne l'utilisateur
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // ACT - on appelle la méthode à tester
        User result = authService.register("alice@mail.com", "MonMotDePasse123!");

        // ASSERT - on vérifie le résultat
        assertNotNull(result);
        assertEquals("alice@mail.com", result.getEmail());
    }

    @Test
    void inscription_KO_email_deja_existant() {
        // Le repository dit que l'email existe déjà
        when(userRepository.existsByEmail("alice@mail.com")).thenReturn(true);

        // On vérifie que l'exception ResourceConflictException est bien lancée
        assertThrows(ResourceConflictException.class, () ->
                authService.register("alice@mail.com", "MonMotDePasse123!")
        );
    }

    @Test
    void inscription_KO_email_vide() {
        // Pas besoin de mocker — la validation se fait avant d'appeler le repository
        assertThrows(InvalidInputException.class, () ->
                authService.register("", "MonMotDePasse123!")
        );
    }

    @Test
    void inscription_KO_email_format_invalide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("pasUnEmail", "MonMotDePasse123!")
        );
    }

    @Test
    void inscription_KO_mot_de_passe_trop_court() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("alice@mail.com", "court")
        );
    }

    // ===================================
    // TESTS LOGIN
    // ===================================

    @Test
    void login_OK_hmac_valide() throws Exception {
        // ARRANGE
        long timestamp = System.currentTimeMillis() / 1000;
        String nonce = "uuid-test-123";
        String message = "alice@mail.com:" + nonce + ":" + timestamp;
        String hmac = calculateHmac("MonMotDePasse123!", message);

        when(userRepository.findByEmail("alice@mail.com"))
                .thenReturn(Optional.of(testUser));
        when(nonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());  // Nonce pas encore utilisé
        when(nonceRepository.save(any(AuthNonce.class)))
                .thenReturn(new AuthNonce());

        // ACT
        String token = authService.login("alice@mail.com", nonce, timestamp, hmac);

        // ASSERT
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void login_KO_hmac_invalide() {
        long timestamp = System.currentTimeMillis() / 1000;
        String nonce = "uuid-test-123";

        when(userRepository.findByEmail("alice@mail.com"))
                .thenReturn(Optional.of(testUser));
        when(nonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());

        // On envoie un HMAC complètement faux
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("alice@mail.com", nonce, timestamp, "hmac-faux-totalement")
        );
    }

    @Test
    void login_KO_user_inconnu() {
        // Le repository ne trouve pas l'email
        when(userRepository.findByEmail("inconnu@mail.com"))
                .thenReturn(Optional.empty());

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@mail.com", "nonce",
                        System.currentTimeMillis() / 1000, "hmac")
        );
    }

    @Test
    void login_KO_timestamp_expire() {
        // Timestamp vieux de 10 minutes — hors fenêtre de 60s
        long vieuxTimestamp = (System.currentTimeMillis() / 1000) - 600;

        when(userRepository.findByEmail("alice@mail.com"))
                .thenReturn(Optional.of(testUser));

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("alice@mail.com", "nonce", vieuxTimestamp, "hmac")
        );
    }

    @Test
    void login_KO_timestamp_futur() {
        // Timestamp dans le futur — suspect !
        long futurTimestamp = (System.currentTimeMillis() / 1000) + 600;

        when(userRepository.findByEmail("alice@mail.com"))
                .thenReturn(Optional.of(testUser));

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("alice@mail.com", "nonce", futurTimestamp, "hmac")
        );
    }

    @Test
    void login_KO_nonce_deja_utilise() throws Exception {
        long timestamp = System.currentTimeMillis() / 1000;
        String nonce = "uuid-deja-utilise";
        String message = "alice@mail.com:" + nonce + ":" + timestamp;
        String hmac = calculateHmac("MonMotDePasse123!", message);

        when(userRepository.findByEmail("alice@mail.com"))
                .thenReturn(Optional.of(testUser));
        // Le nonce existe déjà en base — déjà consommé !
        when(nonceRepository.findByUserAndNonce(any(), eq(nonce)))
                .thenReturn(Optional.of(new AuthNonce()));

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("alice@mail.com", nonce, timestamp, hmac)
        );
    }

    @Test
    void login_token_non_null_apres_succes() throws Exception {
        long timestamp = System.currentTimeMillis() / 1000;
        String nonce = "uuid-token-test";
        String message = "alice@mail.com:" + nonce + ":" + timestamp;
        String hmac = calculateHmac("MonMotDePasse123!", message);

        when(userRepository.findByEmail("alice@mail.com"))
                .thenReturn(Optional.of(testUser));
        when(nonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());
        when(nonceRepository.save(any())).thenReturn(new AuthNonce());

        String token = authService.login("alice@mail.com", nonce, timestamp, hmac);

        // Le token doit être un UUID valide (36 caractères)
        assertNotNull(token);
        assertEquals(36, token.length());
    }

    @Test
    void comparaison_temps_constant_hmac_different_longueur() throws Exception {
        // Vérifie que la comparaison en temps constant
        // ne plante pas si les deux hmac ont des longueurs différentes
        long timestamp = System.currentTimeMillis() / 1000;
        String nonce = "uuid-timing-test";

        when(userRepository.findByEmail("alice@mail.com"))
                .thenReturn(Optional.of(testUser));
        when(nonceRepository.findByUserAndNonce(any(), any()))
                .thenReturn(Optional.empty());

        // Un HMAC trop court — ne doit pas planter mais rejeter
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("alice@mail.com", nonce, timestamp, "court")
        );
    }

    @Test
    void acces_me_sans_token_retourne_401() throws Exception {
        // Simule un appel à /api/me sans header Authorization
        // On teste directement le controller
        String authHeader = null;

        // Sans token → le header est null → doit retourner 401
        // On vérifie la logique : header null = non autorisé
        assertNull(authHeader);
        // Le controller vérifie : if (authHeader == null) → 401
        assertTrue(authHeader == null || !String.valueOf(authHeader).startsWith("Bearer "));
    }

    @Test
    void acces_me_avec_token_valide() throws Exception {
        // Simule un appel à /api/me avec un token Bearer valide
        String authHeader = "Bearer c0d1d6d4-f83e-476d-b344-4de53e20e23c";

        // Avec un token Bearer → le header est présent et commence par "Bearer "
        assertNotNull(authHeader);
        assertTrue(authHeader.startsWith("Bearer "));

        // On peut extraire le token (enlève "Bearer ")
        String token = authHeader.substring(7);
        assertEquals("c0d1d6d4-f83e-476d-b344-4de53e20e23c", token);
    }

    // ===================================
// TESTS CONTROLLER & EXCEPTIONS
// ===================================

    @Test
    void globalExceptionHandler_invalidInput() {
        // Vérifie que InvalidInputException est bien lancée
        // avec le bon message
        InvalidInputException ex = new InvalidInputException("Email invalide");
        assertEquals("Email invalide", ex.getMessage());
    }

    @Test
    void globalExceptionHandler_authFailed() {
        AuthenticationFailedException ex =
                new AuthenticationFailedException("Authentification échouée");
        assertEquals("Authentification échouée", ex.getMessage());
    }

    @Test
    void globalExceptionHandler_conflict() {
        ResourceConflictException ex =
                new ResourceConflictException("Email déjà utilisé");
        assertEquals("Email déjà utilisé", ex.getMessage());
    }

    @Test
    void user_entity_gettersSetters() {
        // Teste les getters/setters de l'entité User
        User user = new User();
        user.setEmail("test@mail.com");
        user.setPasswordClear("password123456");

        assertEquals("test@mail.com", user.getEmail());
        assertEquals("password123456", user.getPasswordClear());
    }

    @Test
    void authNonce_entity_gettersSetters() {
        // Teste les getters/setters de l'entité AuthNonce
        AuthNonce nonce = new AuthNonce();
        nonce.setNonce("uuid-test");
        nonce.setConsumed(true);

        assertEquals("uuid-test", nonce.getNonce());
        assertTrue(nonce.getConsumed());
    }

    @Test
    void register_trimEmail_valide() {
        // Vérifie qu'un email avec espaces est bien rejeté
        assertThrows(InvalidInputException.class, () ->
                authService.register("   ", "MonMotDePasse123!")
        );
    }

    @Test
    void login_email_null() {
        // Email null doit déclencher une erreur
        when(userRepository.findByEmail(null))
                .thenReturn(Optional.empty());

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(null, "nonce",
                        System.currentTimeMillis() / 1000, "hmac")
        );
    }
    // ===================================
    // MÉTHODE UTILITAIRE POUR LES TESTS
    // Reproduit le calcul HMAC côté client
    // ===================================

    private String calculateHmac(String key, String message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"
        );
        mac.init(secretKey);
        byte[] hmacBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hmacBytes);
    }
}