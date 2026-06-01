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
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;


@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final AuthUtil authUtil;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;


    @Transactional
    public AuthResponseDto login(LoginRequestDto loginRequestDto, HttpServletResponse response) {
        // authenticate credential
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDto.getEmail(), loginRequestDto.getPassword())
        );

        // get principle
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        String accessToken = authUtil.generateAccessToken(userDetails);
        String refreshToken = authUtil.generateRefreshToken(userDetails);
        User user = userRepository.findByEmail(userDetails.getUsername()).orElseThrow();
        RefreshToken savedRefreshToken = RefreshToken.builder()
                .token(refreshToken)
                .user(user)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();
        refreshTokenRepository.save(savedRefreshToken);

        // set in cookie
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(false) // set to false for local development over HTTP
                .path("/")
                .maxAge(60 * 60 * 24 * 7) // 7 days
                .sameSite("Lax")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return new AuthResponseDto("Login success", accessToken, refreshToken);
    }

    public AuthResponseDto register(RegisterRequestDto registerRequestDto) {
        userRepository.findByEmail(registerRequestDto.getEmail()).ifPresent(user -> {
            throw new RuntimeException("User already exists");
        });

        User user = new User();
        user.setFullName(registerRequestDto.getFullName());
        user.setEmail(registerRequestDto.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequestDto.getPassword()));
        user.setActive(true);
        userRepository.save(user);
        return new AuthResponseDto("User registered successfully", null, null);
    }

    public Object refreshToken(HttpServletRequest request) {
        try {
            String refreshToken = null;
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals("refreshToken")) {
                        refreshToken = cookie.getValue();
                    }
                }
            }
            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Refresh token missing from cookies"));
            }
            
            String username = authUtil.getUserFromToken(refreshToken);
            RefreshToken savedToken = refreshTokenRepository.findByToken(refreshToken)
                    .orElseThrow(() -> new RuntimeException("Token not found in database"));

            if (savedToken.getRevoked()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Refresh token is revoked"));
            }
            if (savedToken.getExpiresAt().isBefore(LocalDateTime.now())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "Refresh token is expired"));
            }

            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            CustomUserDetails userDetails = new CustomUserDetails(user);
            String newAccessToken = authUtil.generateAccessToken(userDetails);

            return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid refresh token: " + e.getMessage()));
        }
    }

    public Object logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refreshToken")) {
                    String token = cookie.getValue();
                    refreshTokenRepository
                            .findByToken(token)
                            .ifPresent(refreshToken -> {
                                refreshToken.setRevoked(true);
                                refreshTokenRepository.save(refreshToken);
                            });
                    
                    ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                            .httpOnly(true)
                            .secure(false)
                            .path("/")
                            .maxAge(0)
                            .sameSite("Lax")
                            .build();
                    response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());
                }
            }
        }
        return ResponseEntity.ok(Map.of("message", "Logout successful"));
    }
}
