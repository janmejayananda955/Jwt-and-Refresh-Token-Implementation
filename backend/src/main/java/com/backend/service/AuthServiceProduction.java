package com.backend.service;

import com.backend.dto.AuthResponseDto;
import com.backend.dto.LoginRequestDto;
import com.backend.dto.RegisterRequestDto;
import com.backend.entity.RefreshToken;
import com.backend.entity.User;
import com.backend.repository.RefreshTokenRepository;
import com.backend.repository.UserRepository;
import com.backend.security.AuthUtil;
import com.backend.security.CustomUserDetails;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceProduction {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthUtil authUtil;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public AuthResponseDto login(LoginRequestDto loginRequestDto, HttpServletResponse response) {
        // 1. Authenticate credentials
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDto.getEmail(), loginRequestDto.getPassword())
        );

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 2. Generate tokens
        String accessToken = authUtil.generateAccessToken(userDetails);
        String newRefreshToken = UUID.randomUUID().toString();

        // 3. Save new Refresh Token
        saveNewRefreshToken(user, newRefreshToken);

        // 4. Set Refresh Token as HTTP-Only Cookie with restricted Path
        setRefreshTokenCookie(response, newRefreshToken);

        return new AuthResponseDto("Login success", accessToken, null);
    }

    @Transactional
    public AuthResponseDto refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String token = getRefreshTokenFromCookies(request)
                .orElseThrow(() -> new RuntimeException("Refresh Token cookie missing"));

        // Find token record in DB
        RefreshToken savedToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Refresh Token not recognized"));

        // Check expiration or revocation
        if (savedToken.getExpiresAt().isBefore(LocalDateTime.now()) || savedToken.getRevoked()) {
            // --- SECURITY ATTACK DETECTION ---
            // If the token is revoked, someone might be attempting to reuse an intercepted token.
            if (savedToken.getRevoked()) {
                log.warn("DETECTED ATTACK: Attempted reuse of revoked Refresh Token for user: {}", savedToken.getUser().getEmail());
                // Force revoke all user sessions
                refreshTokenRepository.deleteByUser(savedToken.getUser());
            }
            throw new RuntimeException("Session expired or invalid");
        }

        // --- REFRESH TOKEN ROTATION (RTR) ---
        // 1. Revoke/invalidate the old refresh token
        savedToken.setRevoked(true);
        refreshTokenRepository.save(savedToken);

        // 2. Generate new tokens
        User user = savedToken.getUser();
        CustomUserDetails userDetails = new CustomUserDetails(user);
        
        String newAccessToken = authUtil.generateAccessToken(userDetails);
        String newRefreshToken = UUID.randomUUID().toString();

        // 3. Save the new refresh token record
        saveNewRefreshToken(user, newRefreshToken);

        // 4. Set new HTTP-Only cookie to rotate it
        setRefreshTokenCookie(response, newRefreshToken);

        return new AuthResponseDto("Token refreshed", newAccessToken, null);
    }

    @Transactional
    public AuthResponseDto logout(HttpServletRequest request, HttpServletResponse response) {
        // Clear refresh token from database if present
        getRefreshTokenFromCookies(request).flatMap(refreshTokenRepository::findByToken)
                .ifPresent(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                });

        // Delete refresh cookie by setting Max-Age = 0
        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false) // Set to true in HTTPS production
                .sameSite("Lax")
                .path("/api/auth/refresh") // Match the restricted path
                .maxAge(0) // Immediately expires the cookie in client browser
                .build();
        response.addHeader("Set-Cookie", deleteCookie.toString());

        return new AuthResponseDto("Logout success", null, null);
    }

    // --- Helper Methods ---

    private void saveNewRefreshToken(User user, String tokenValue) {
        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setToken(tokenValue);
        refreshTokenEntity.setUser(user);
        refreshTokenEntity.setExpiresAt(LocalDateTime.now().plusDays(7));
        refreshTokenEntity.setRevoked(false);
        refreshTokenRepository.save(refreshTokenEntity);
    }

    private void setRefreshTokenCookie(HttpServletResponse response, String tokenValue) {
        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenValue)
                .httpOnly(true)
                .secure(false)                // Set to 'true' in HTTPS production environments
                .sameSite("Lax")              // Use 'Strict' for strict CSRF mitigation in prod
                .path("/api/auth/refresh")    // --- PATH RESTRICTION: only sent to refresh endpoint ---
                .maxAge(7 * 24 * 60 * 60)     // Expires in 7 days
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    private Optional<String> getRefreshTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() == null) return Optional.empty();
        for (Cookie cookie : request.getCookies()) {
            if ("refreshToken".equals(cookie.getName())) {
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }
}
