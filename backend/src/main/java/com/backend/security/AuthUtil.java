package com.backend.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class AuthUtil {

    @Value("${jwt.secret}")
    private String jwtSecretToken;

    private SecretKey getSecretKey(){
        return Keys.hmacShaKeyFor(jwtSecretToken.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(CustomUserDetails userDetails){
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim("userId", userDetails.getUserId())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 3))
                .signWith(getSecretKey())
                .compact();
    }

    public String getUserFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public String generateRefreshToken(CustomUserDetails userDetails) {
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim("userId", userDetails.getUserId())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 7)) // 7 days
                .signWith(getSecretKey())
                .compact();
    }
}
