package com.sai.oauth_sso_server.service;

import com.sai.oauth_sso_server.model.OAuthClient;
import com.sai.oauth_sso_server.model.User;
import com.sai.oauth_sso_server.repository.OAuthClientRepository;
import com.sai.oauth_sso_server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class OAuthService {

    private final OAuthClientRepository clientRepository;
    private final UserRepository userRepository;
    private final RedisTemplate<String, String> redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public OAuthClient validateClient(String clientId, String redirectUri) {
        OAuthClient client = clientRepository.findById(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown client: " + clientId));

        // Only validate redirectUri for authorization_code flow
        if (redirectUri != null && !client.getRedirectUris().contains(redirectUri)) {
            throw new IllegalArgumentException("Invalid redirect URI");
        }

        return client;
    }

    public String generateAuthCode(String userId, String clientId, String scope) {
        // 1. Generate random code
        String code = UUID.randomUUID().toString();

        // 2. Store in Redis: code → userId:clientId:scope (expires in 5 min)
        String value = userId + ":" + clientId + ":" + scope;
        redisTemplate.opsForValue().set(
                "auth_code:" + code,
                value,
                300,
                TimeUnit.SECONDS
        );

        return code;
    }

    public User authenticateUser(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        if (!user.isActive()) {
            throw new IllegalStateException("Account is disabled");
        }

        return user;
    }

    public String[] exchangeCode(String code) {
        // 1. Get value from Redis
        String value = redisTemplate.opsForValue().get("auth_code:" + code);
        if (value == null) {
            throw new IllegalArgumentException("Invalid or expired authorization code");
        }

        // 2. Delete immediately — one time use!
        redisTemplate.delete("auth_code:" + code);

        // 3. Return [userId, clientId, scope]
        return value.split(":");
    }
}