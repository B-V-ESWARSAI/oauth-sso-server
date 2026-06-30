package com.sai.oauth_sso_server;

import com.sai.oauth_sso_server.dto.RegisterRequest;
import com.sai.oauth_sso_server.model.User;
import com.sai.oauth_sso_server.repository.RefreshTokenRepository;
import com.sai.oauth_sso_server.repository.UserRepository;
import com.sai.oauth_sso_server.service.AuthService;
import com.sai.oauth_sso_server.service.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private TokenService tokenService;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @InjectMocks
    private AuthService authService;

    private RegisterRequest registerRequest;

    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest();
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("password123");
        registerRequest.setFullName("Test User");
    }

    @Test
    void register_Success_WhenEmailIsNew() {
        // Arrange
        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("hashedPassword");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(UUID.randomUUID());
            return user;
        });

        // Act
        User result = authService.register(registerRequest);

        // Assert
        assertNotNull(result);
        assertEquals("test@example.com", result.getEmail());
        assertEquals("hashedPassword", result.getPasswordHash());
        assertEquals(List.of("USER"), result.getRoles());
        assertTrue(result.isActive());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void register_ThrowsException_WhenEmailAlreadyExists() {
        // Arrange
        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

        // Act & Assert
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> authService.register(registerRequest)
        );
        assertEquals("Email already registered", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void login_ThrowsException_WhenUserNotFound() {
        // Arrange
        when(userRepository.findByEmail("notfound@example.com"))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(
                IllegalArgumentException.class,
                () -> authService.login("notfound@example.com", "anyPassword")
        );
    }

    @Test
    void login_ThrowsException_WhenPasswordIsWrong() {
        // Arrange
        User user = new User();
        user.setEmail("test@example.com");
        user.setPasswordHash("hashedPassword");
        user.setActive(true);

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongPassword", "hashedPassword"))
                .thenReturn(false);

        // Act & Assert
        assertThrows(
                IllegalArgumentException.class,
                () -> authService.login("test@example.com", "wrongPassword")
        );
    }

    @Test
    void login_ThrowsException_WhenAccountIsDisabled() {
        // Arrange
        User user = new User();
        user.setEmail("test@example.com");
        user.setPasswordHash("hashedPassword");
        user.setActive(false);

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));

        // Act & Assert
        assertThrows(
                IllegalStateException.class,
                () -> authService.login("test@example.com", "password123")
        );
    }
}