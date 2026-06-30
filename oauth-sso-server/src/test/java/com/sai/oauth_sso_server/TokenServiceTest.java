package com.sai.oauth_sso_server;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sai.oauth_sso_server.model.User;
import com.sai.oauth_sso_server.repository.RefreshTokenRepository;
import com.sai.oauth_sso_server.service.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private TokenService tokenService;
    private User testUser;

    @BeforeEach
    void setUp() throws Exception {
        // Generate a real RSA key pair for testing
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        Algorithm algorithm = Algorithm.RSA256(
                (RSAPublicKey) keyPair.getPublic(),
                (RSAPrivateKey) keyPair.getPrivate()
        );

        tokenService = new TokenService(algorithm, refreshTokenRepository);

        // Manually set the @Value fields using reflection (since no Spring context here)
        setField(tokenService, "accessTokenExpiry", 900000L);
        setField(tokenService, "refreshTokenExpiry", 604800000L);

        testUser = new User();
        testUser.setId(UUID.randomUUID());
        testUser.setEmail("test@example.com");
        testUser.setFullName("Test User");
        testUser.setRoles(List.of("USER"));
    }

    private void setField(Object target, String fieldName, Object value) throws Exception {
        var field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    @Test
    void generateAccessToken_ContainsCorrectClaims() {
        // Act
        String token = tokenService.generateAccessToken(testUser);

        // Assert
        assertNotNull(token);
        DecodedJWT decoded = tokenService.validateToken(token);
        assertEquals(testUser.getId().toString(), decoded.getSubject());
        assertEquals("test@example.com", decoded.getClaim("email").asString());
        assertEquals("Test User", decoded.getClaim("fullName").asString());
        assertEquals(List.of("USER"), decoded.getClaim("roles").asList(String.class));
    }

    @Test
    void validateToken_ThrowsException_WhenTokenIsInvalid() {
        // Act & Assert
        assertThrows(
                IllegalStateException.class,
                () -> tokenService.validateToken("invalid.token.here")
        );
    }

    @Test
    void validateToken_ThrowsException_WhenTokenIsTampered() {
        // Arrange
        String validToken = tokenService.generateAccessToken(testUser);
        String tamperedToken = validToken.substring(0, validToken.length() - 5) + "XXXXX";

        // Act & Assert
        assertThrows(
                IllegalStateException.class,
                () -> tokenService.validateToken(tamperedToken)
        );
    }
}