package com.backend.controller;

import com.backend.dto.LoginRequestDto;
import com.backend.dto.RegisterRequestDto;
import com.backend.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDto loginRequestDto, HttpServletResponse response){
        return ResponseEntity.ok(authService.login(loginRequestDto, response));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequestDto registerRequestDto){
        return ResponseEntity.ok(authService.register(registerRequestDto));
    }

    @PostMapping("/refresh")
    public Object refresh(HttpServletRequest request){
        return authService.refreshToken(request);
    }

    @PostMapping("/logout")
    public Object logout(HttpServletRequest request, HttpServletResponse response){
        return authService.logout(request, response);
    }

}
