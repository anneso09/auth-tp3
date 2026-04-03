package com.example.auth_tp3.entity;

// Ces imports disent à Java quels outils on utilise
import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

/**
 * Représente un utilisateur dans la base de données.
 * Cette classe est liée à la table "users" dans MySQL.
 */
@Data                    // Lombok génère automatiquement les getters, setters, toString
@Entity                  // Dit à Spring que cette classe est liée à une table MySQL
@Table(name = "users")   // Précise le nom exact de la table dans MySQL
public class User {

    @Id                                                    // C'est la clé primaire
    @GeneratedValue(strategy = GenerationType.IDENTITY)   // MySQL génère l'ID automatiquement (AUTO_INCREMENT)
    private Long id;

    @Column(nullable = false, unique = true)   // email obligatoire et unique
    private String email;

    @Column(name = "password_clear", nullable = false)   // nom exact de la colonne dans MySQL
    private String passwordClear;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist   // Cette méthode s'exécute automatiquement AVANT chaque insertion en base
    protected void onCreate() {
        createdAt = LocalDateTime.now();   // Remplit la date automatiquement
    }
}