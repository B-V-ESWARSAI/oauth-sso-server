package com.sai.oauth_sso_server.controller;

import com.sai.oauth_sso_server.dto.RefreshTokenRequest;
import com.sai.oauth_sso_server.dto.RegisterRequest;
import com.sai.oauth_sso_server.model.User;
import com.sai.oauth_sso_server.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

import com.sai.oauth_sso_server.dto.LoginRequest;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import com.sai.oauth_sso_server.service.TokenService;
import com.sai.oauth_sso_server.repository.UserRepository;
import java.util.List;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;
    private final RedisTemplate<String, String> redisTemplate;
//    private final TokenService tokenService;
private final java.security.interfaces.RSAPublicKey rsaPublicKey;
    private final UserRepository userRepository;
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
    @PostMapping("/introspect")
    public ResponseEntity<?> introspect(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        Map<String, Object> response = new HashMap<>();

        if (token == null || token.isBlank()) {
            response.put("active", false);
            return ResponseEntity.ok(response);
        }

        // Check blacklist first
        if (Boolean.TRUE.equals(redisTemplate.hasKey("blacklist:" + token))) {
            response.put("active", false);
            return ResponseEntity.ok(response);
        }

        try {
            DecodedJWT jwt = tokenService.validateToken(token);
            response.put("active", true);
            response.put("sub", jwt.getSubject());
            response.put("email", jwt.getClaim("email").asString());
            response.put("roles", jwt.getClaim("roles").asList(String.class));
            response.put("fullName", jwt.getClaim("fullName").asString());
            response.put("exp", jwt.getExpiresAt().getTime() / 1000);
            response.put("iss", jwt.getIssuer());
        } catch (Exception e) {
            response.put("active", false);
        }

        return ResponseEntity.ok(response);
    }
    @GetMapping("/jwks")
    public ResponseEntity<?> jwks() throws Exception {
        java.security.interfaces.RSAPublicKey publicKey =
                (java.security.interfaces.RSAPublicKey) rsaPublicKey;

        String n = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(publicKey.getModulus().toByteArray());
        String e = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(publicKey.getPublicExponent().toByteArray());

        Map<String, Object> key = new HashMap<>();
        key.put("kty", "RSA");
        key.put("use", "sig");
        key.put("alg", "RS256");
        key.put("n", n);
        key.put("e", e);

        Map<String, Object> response = new HashMap<>();
        response.put("keys", List.of(key));

        return ResponseEntity.ok(response);
    }
    @GetMapping("/admin/users")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll()
                .stream()
                .map(u -> {
                    Map<String, Object> user = new HashMap<>();
                    user.put("id", u.getId());
                    user.put("email", u.getEmail());
                    user.put("fullName", u.getFullName());
                    user.put("roles", u.getRoles());
                    user.put("isActive", u.isActive());
                    return user;
                })
                .toList()
        );
    }

    @PutMapping("/admin/users/{id}/roles")
    public ResponseEntity<?> updateRoles(
            @PathVariable String id,
            @RequestBody Map<String, List<String>> request) {
        User user = userRepository.findById(UUID.fromString(id))
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setRoles(request.get("roles"));
        userRepository.save(user);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Roles updated successfully");
        response.put("userId", id);
        response.put("roles", user.getRoles());
        return ResponseEntity.ok(response);
    }


    // Simple inner response record — keeps password hash out of the response
    record RegisterResponse(String id, String email, String fullName, java.util.List<String> roles) {}
}