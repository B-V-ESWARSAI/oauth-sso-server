package com.sai.oauth_sso_server.controller;

import com.sai.oauth_sso_server.dto.RefreshTokenRequest;
import com.sai.oauth_sso_server.dto.RegisterRequest;
import com.sai.oauth_sso_server.model.User;
import com.sai.oauth_sso_server.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;
import com.sai.oauth_sso_server.dto.LoginRequest;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import com.sai.oauth_sso_server.service.TokenService;
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        User savedUser = authService.register(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(
                new RegisterResponse(
                        savedUser.getId().toString(),
                        savedUser.getEmail(),
                        savedUser.getFullName(),
                        savedUser.getRoles()
                )
        );
    }
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        Map<String, Object> tokens = authService.login(
                request.getEmail(),
                request.getPassword()
        );
        return ResponseEntity.ok(tokens);
    }
    @GetMapping("/userinfo")
    public ResponseEntity<?> userInfo(HttpServletRequest request) {
        // Everything we need is already in the Security Context
        // set by JwtAuthFilter — no DB call, no second token parse needed
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        String token = request.getHeader("Authorization").substring(7);
        DecodedJWT jwt = tokenService.validateToken(token);

        Map<String, Object> response = new HashMap<>();
        response.put("userId", authentication.getPrincipal());
        response.put("email", jwt.getClaim("email").asString());
        response.put("fullName", jwt.getClaim("fullName").asString());
        response.put("roles", jwt.getClaim("roles").asList(String.class));

        return ResponseEntity.ok(response);
    }
    @PostMapping("/token/refresh")
    public ResponseEntity<?> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        Map<String, Object> tokens = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(tokens);
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("No token provided");
        }
        authService.logout(authHeader);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Logged out successfully");
        response.put("status", 200);
        return ResponseEntity.ok(response);
    }


    // Simple inner response record — keeps password hash out of the response
    record RegisterResponse(String id, String email, String fullName, java.util.List<String> roles) {}
}