package com.sai.oauth_sso_server.service;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.sai.oauth_sso_server.dto.RegisterRequest;
import com.sai.oauth_sso_server.model.User;
import com.sai.oauth_sso_server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.sai.oauth_sso_server.model.RefreshToken;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import com.sai.oauth_sso_server.repository.RefreshTokenRepository;
import java.time.LocalDateTime;
import org.springframework.data.redis.core.RedisTemplate;
import java.util.concurrent.TimeUnit;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.util.UUID;



@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RedisTemplate<String, String> redisTemplate;
    public User register(RegisterRequest request) {
        // 1. Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalStateException("Email already registered");
        }

        // 2. Hash the password
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        // 3. Build the User entity
        User user = new User();
        user.setEmail(request.getEmail());
        user.setPasswordHash(hashedPassword);
        user.setFullName(request.getFullName());
        user.setRoles(List.of("USER"));
        user.setActive(true);

        // 4. Save to database
        return userRepository.save(user);
    }

    public Map<String, Object> login(String email, String password) {
        // 1. Find user by email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        // 2. Check if account is active
        if (!user.isActive()) {
            throw new IllegalStateException("Account is disabled");
        }

        // 3. Verify password
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid email or password");
        }

        // 4. Generate both tokens
        String accessToken = tokenService.generateAccessToken(user);
        RefreshToken refreshToken = tokenService.generateRefreshToken(user);

        // 5. Return both in a map
        Map<String, Object> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken.getToken());
        tokens.put("tokenType", "Bearer");
        tokens.put("expiresIn", 900);
        return tokens;
    }
    public Map<String, Object> refreshToken(String refreshTokenValue) {

        // 1. Find refresh token in DB
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenValue)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        // 2. Check if revoked
        if (refreshToken.isRevoked()) {
            throw new IllegalStateException("Refresh token has been revoked");
        }

        // 3. Check if expired
        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("Refresh token has expired");
        }

        // 4. Revoke old refresh token (rotation)
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);

        // 5. Generate new tokens
        User user = refreshToken.getUser();
        String newAccessToken = tokenService.generateAccessToken(user);
        RefreshToken newRefreshToken = tokenService.generateRefreshToken(user);

        // 6. Return new tokens
        Map<String, Object> tokens = new HashMap<>();
        tokens.put("accessToken", newAccessToken);
        tokens.put("refreshToken", newRefreshToken.getToken());
        tokens.put("tokenType", "Bearer");
        tokens.put("expiresIn", 900);
        return tokens;
    }
    public void logout(String authHeader) {

        // 1. Extract token from "Bearer xxxx"
        String token = authHeader.substring(7);

        // 2. Validate token and get expiry
        DecodedJWT jwt = tokenService.validateToken(token);

        // 3. Calculate remaining TTL in seconds
        long expiryTime = jwt.getExpiresAt().getTime();
        long currentTime = System.currentTimeMillis();
        long ttlSeconds = (expiryTime - currentTime) / 1000;

        // 4. Blacklist token in Redis until it naturally expires
        if (ttlSeconds > 0) {
            redisTemplate.opsForValue().set(
                    "blacklist:" + token,
                    "revoked",
                    ttlSeconds,
                    TimeUnit.SECONDS
            );
        }

        // 5. Revoke all refresh tokens for this user in DB
        UUID userId = UUID.fromString(jwt.getSubject());
        refreshTokenRepository.revokeAllByUserId(userId);
    }
    public DecodedJWT validateToken(String token) {
        return tokenService.validateToken(token);
    }
}