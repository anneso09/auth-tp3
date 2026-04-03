package com.example.auth_tp3.repository;

import com.example.auth_tp3.entity.AuthNonce;
import com.example.auth_tp3.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

/**
 * Repository pour accéder aux nonces dans MySQL.
 * Permet de vérifier si un nonce a déjà été utilisé
 * pour protéger contre les attaques par rejeu.
 */
@Repository
public interface NonceRepository extends JpaRepository<AuthNonce, Long> {

    // Cherche un nonce précis pour un utilisateur précis
    // SELECT * FROM auth_nonce WHERE user_id = ? AND nonce = ?
    Optional<AuthNonce> findByUserAndNonce(User user, String nonce);
}