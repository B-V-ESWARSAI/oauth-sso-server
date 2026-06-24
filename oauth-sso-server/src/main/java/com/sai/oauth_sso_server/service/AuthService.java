package com.sai.oauth_sso_server.service;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.sai.oauth_sso_server.dto.RegisterRequest;
import com.sai.oauth_sso_server.model.User;
import com.sai.oauth_sso_server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

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

    public String login(String email, String password) {
        // 1. Find user by email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        // 2. Check if account is active
        if (!user.isActive()) {
            throw new IllegalStateException("Account is disabled");
        }

        // 3. Verify password against stored hash
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid email or password");
        }

        // 4. Generate and return JWT access token
        return tokenService.generateAccessToken(user);
    }
    public DecodedJWT validateToken(String token) {
        return tokenService.validateToken(token);
    }
}