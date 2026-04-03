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
 * Tests unitaires pour AuthService.
 * On teste la logique métier sans démarrer le serveur
 * et sans toucher à la vraie base de données.
 *
 * Mockito simule les repositories — on contrôle
 * exactement ce qu'ils retournent dans chaque test.
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