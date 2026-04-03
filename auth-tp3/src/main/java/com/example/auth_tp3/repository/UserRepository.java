package com.example.auth_tp3.repository;

import com.example.auth_tp3.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

/**
 * Repository pour accéder aux données des utilisateurs dans MySQL.
 * JpaRepository nous donne automatiquement : save(), findById(), findAll(), delete()...
 * On ajoute juste les méthodes spécifiques dont on a besoin.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Spring génère automatiquement la requête SQL :
    // SELECT * FROM users WHERE email = ?
    Optional<User> findByEmail(String email);

    // Vérifie si un email existe déjà dans la base
    // SELECT COUNT(*) FROM users WHERE email = ?
    boolean existsByEmail(String email);
}