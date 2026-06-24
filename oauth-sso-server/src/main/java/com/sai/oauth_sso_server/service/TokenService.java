package com.sai.oauth_sso_server.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sai.oauth_sso_server.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final Algorithm jwtAlgorithm;

    @Value("${jwt.access-token-expiry}")
    private long accessTokenExpiry;

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