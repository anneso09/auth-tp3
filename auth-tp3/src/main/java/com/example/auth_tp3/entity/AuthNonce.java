package com.example.auth_tp3.entity;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

/**
 * Représente un nonce d'authentification dans la base de données.
 * Chaque nonce est lié à un utilisateur et ne peut être utilisé qu'une seule fois.
 * Cela empêche les attaques par rejeu (replay attacks).
 */
@Data
@Entity
@Table(name = "auth_nonce")
public class AuthNonce {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Lien vers l'utilisateur — user_id dans la table auth_nonce
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Le nonce UUID généré par le client
    @Column(nullable = false)
    private String nonce;

    // Date d'expiration — now + 2 minutes
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    // False = pas encore utilisé, True = déjà consommé
    @Column(nullable = false)
    private Boolean consumed = false;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}