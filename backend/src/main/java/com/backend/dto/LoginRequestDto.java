package com.backend.dto;


import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class LoginRequestDto {
    private String email;
    private String password;
}
