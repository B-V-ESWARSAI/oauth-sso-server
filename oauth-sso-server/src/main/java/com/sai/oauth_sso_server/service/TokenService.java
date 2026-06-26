package com.sai.oauth_sso_server.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sai.oauth_sso_server.model.RefreshToken;
import com.sai.oauth_sso_server.model.User;
import com.sai.oauth_sso_server.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final Algorithm jwtAlgorithm;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.access-token-expiry}")
    private long accessTokenExpiry;

    @Value("${jwt.refresh-token-expiry}")
    private long refreshTokenExpiry;

    public String generateAccessToken(User user) {
        return JWT.create()
                .withSubject(user.getId().toString())
                .withClaim("email", user.getEmail())
                .withClaim("roles", user.getRoles())
                .withClaim("fullName", user.getFullName())
                .withIssuer("oauth-sso-server")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenExpiry))
                .sign(jwtAlgorithm);
    }

    public RefreshToken generateRefreshToken(User user) {
        String tokenValue = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now()
                .plusSeconds(refreshTokenExpiry / 1000);

        RefreshToken refreshToken = new RefreshToken(user, tokenValue, expiresAt);
        return refreshTokenRepository.save(refreshToken);
    }

    public DecodedJWT validateToken(String token) {
        try {
            return JWT.require(jwtAlgorithm)
                    .withIssuer("oauth-sso-server")
                    .build()
                    .verify(token);
        } catch (JWTVerificationException e) {
            throw new IllegalStateException("Invalid or expired token: " + e.getMessage());
        }
    }
}