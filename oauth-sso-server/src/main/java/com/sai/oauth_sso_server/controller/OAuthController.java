package com.sai.oauth_sso_server.controller;

import com.sai.oauth_sso_server.model.OAuthClient;
import com.sai.oauth_sso_server.model.User;
import com.sai.oauth_sso_server.model.RefreshToken;
import com.sai.oauth_sso_server.repository.UserRepository;
import com.sai.oauth_sso_server.service.OAuthService;
import com.sai.oauth_sso_server.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OAuthService oAuthService;
    private final TokenService tokenService;
    private final UserRepository userRepository;

    // Step 1: Client validates and gets auth code
    // In real SSO this shows a login page — here we accept
    // credentials directly for simplicity (Postman testable)
    @PostMapping("/authorize")
    public ResponseEntity<?> authorize(@RequestBody Map<String, String> request) {
        String clientId    = request.get("clientId");
        String redirectUri = request.get("redirectUri");
        String email       = request.get("email");
        String password    = request.get("password");
        String scope       = request.get("scope");
        String state       = request.get("state");

        // 1. Validate client + redirect URI
        OAuthClient client = oAuthService.validateClient(clientId, redirectUri);

        // 2. Authenticate user
        User user = oAuthService.authenticateUser(email, password);

        // 3. Validate scopes
        for (String s : scope.split(" ")) {
            if (!client.getScopes().contains(s)) {
                throw new IllegalArgumentException("Invalid scope: " + s);
            }
        }

        // 4. Generate auth code
        String code = oAuthService.generateAuthCode(
                user.getId().toString(), clientId, scope
        );

        // 5. Return redirect URL with code
        Map<String, Object> response = new HashMap<>();
        response.put("redirectUrl", redirectUri + "?code=" + code + "&state=" + state);
        response.put("code", code);
        response.put("state", state);

        return ResponseEntity.ok(response);
    }

    // Step 2: Client exchanges code for tokens
    @PostMapping("/token")
    public ResponseEntity<?> token(@RequestBody Map<String, String> request) {
        String grantType    = request.get("grantType");
        String clientId     = request.get("clientId");
        String clientSecret = request.get("clientSecret");

        // CLIENT CREDENTIALS FLOW
        if ("client_credentials".equals(grantType)) {
            // 1. Find client
            OAuthClient client = oAuthService.validateClient(
                    clientId,
                    // client_credentials doesn't need redirectUri validation
                    // so we pass the first registered one
                    null
            );

            if (!client.getClientSecret().equals(clientSecret)) {
                throw new IllegalArgumentException("Invalid client secret");
            }

            // 2. Issue a token representing the client itself (no user)
            String accessToken = tokenService.generateClientToken(clientId, client.getScopes());

            Map<String, Object> response = new HashMap<>();
            response.put("accessToken", accessToken);
            response.put("tokenType", "Bearer");
            response.put("expiresIn", 900);
            response.put("scope", client.getScopes());
            return ResponseEntity.ok(response);
        }

        // AUTHORIZATION CODE FLOW
        String code        = request.get("code");
        String redirectUri = request.get("redirectUri");

        // 1. Validate client
        OAuthClient client = oAuthService.validateClient(clientId, redirectUri);
        if (!client.getClientSecret().equals(clientSecret)) {
            throw new IllegalArgumentException("Invalid client secret");
        }

        // 2. Exchange code
        String[] parts = oAuthService.exchangeCode(code);
        String userId  = parts[0];

        // 3. Load user
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // 4. Generate tokens
        String accessToken = tokenService.generateAccessToken(user);
        RefreshToken refreshToken = tokenService.generateRefreshToken(user);

        Map<String, Object> response = new HashMap<>();
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken.getToken());
        response.put("tokenType", "Bearer");
        response.put("expiresIn", 900);
        return ResponseEntity.ok(response);
    }
}