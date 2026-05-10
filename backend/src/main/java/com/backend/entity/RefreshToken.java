package com.backend.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String token;

    @CreationTimestamp
    private LocalDateTime createdAt;
@UpdateTimestamp
    private LocalDateTime updatedAt;

    private LocalDateTime expiresAt;

    private Boolean revoked;

    @ManyToOne
    // because one user can have multiple refresh tokens for different devices/browsers
    private User user;
}
