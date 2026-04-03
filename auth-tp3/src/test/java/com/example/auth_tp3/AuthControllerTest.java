package com.example.auth_tp3;

import com.example.auth_tp3.exception.AuthenticationFailedException;
import com.example.auth_tp3.exception.InvalidInputException;
import com.example.auth_tp3.exception.ResourceConflictException;
import com.example.auth_tp3.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;

import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests d'intégration pour AuthController.
 * Utilise MockMvc pour simuler les requêtes HTTP
 * sans démarrer un vrai serveur.
 *
 * @WebMvcTest(controllers = com.example.auth_tp3.controller.AuthController.class) charge uniquement la couche controller
 * et non toute l'application Spring Boot.
 */
@WebMvcTest(controllers = com.example.auth_tp3.controller.AuthController.class)
class AuthControllerTest {

    // MockMvc simule les requêtes HTTP
    @Autowired
    private MockMvc mockMvc;

    // On mocke le service car on teste uniquement le controller
    @MockitoBean
    private AuthService authService;

    // ===================================
    // TESTS REGISTER
    // ===================================

    @Test
    void register_retourne_201() throws Exception {
        // Le service retourne un utilisateur mock
        com.example.auth_tp3.entity.User user = new com.example.auth_tp3.entity.User();
        user.setEmail("alice@mail.com");
        when(authService.register(anyString(), anyString())).thenReturn(user);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"alice@mail.com\",\"password\":\"MonMotDePasse123!\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("Inscription réussie"));
    }

    @Test
    void register_retourne_409_si_email_existe() throws Exception {
        when(authService.register(anyString(), anyString()))
                .thenThrow(new ResourceConflictException("Email déjà utilisé"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"alice@mail.com\",\"password\":\"MonMotDePasse123!\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void register_retourne_400_si_donnees_invalides() throws Exception {
        when(authService.register(anyString(), anyString()))
                .thenThrow(new InvalidInputException("Email invalide"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"\",\"password\":\"MonMotDePasse123!\"}"))
                .andExpect(status().isBadRequest());
    }

    // ===================================
    // TESTS LOGIN
    // ===================================

    @Test
    void login_retourne_200_avec_token() throws Exception {
        when(authService.login(anyString(), anyString(), anyLong(), anyString()))
                .thenReturn("token-uuid-123");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"alice@mail.com\",\"nonce\":\"uuid\",\"timestamp\":1234567890,\"hmac\":\"abc\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("token-uuid-123"));
    }

    @Test
    void login_retourne_401_si_hmac_invalide() throws Exception {
        when(authService.login(anyString(), anyString(), anyLong(), anyString()))
                .thenThrow(new AuthenticationFailedException("Authentification échouée"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"alice@mail.com\",\"nonce\":\"uuid\",\"timestamp\":1234567890,\"hmac\":\"faux\"}"))
                .andExpect(status().isUnauthorized());
    }

    // ===================================
    // TESTS /api/me
    // ===================================

    @Test
    void getMe_retourne_200_avec_token_valide() throws Exception {
        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Bearer token-valide-123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Accès autorisé"));
    }

    @Test
    void getMe_retourne_401_sans_token() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getMe_retourne_401_token_mal_forme() throws Exception {
        mockMvc.perform(get("/api/me")
                        .header("Authorization", "InvalidToken"))
                .andExpect(status().isUnauthorized());
    }
}