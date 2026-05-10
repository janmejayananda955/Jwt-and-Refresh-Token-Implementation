package com.backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Getter
@Setter
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column
    private String fullName;

    @Column(unique = true)
    private String email;

    @Column
    private String password;

    @Column
    private boolean isActive;

    @Column
    private LocalDateTime createdAt;


}





