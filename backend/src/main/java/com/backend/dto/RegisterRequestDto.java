package com.backend.dto;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class RegisterRequestDto {
    private String fullName;
    private String email;
    private String password;
}
