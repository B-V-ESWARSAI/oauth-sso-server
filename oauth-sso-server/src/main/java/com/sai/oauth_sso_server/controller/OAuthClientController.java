package com.sai.oauth_sso_server.controller;

import com.sai.oauth_sso_server.dto.OAuthClientRequest;
import com.sai.oauth_sso_server.model.OAuthClient;
import com.sai.oauth_sso_server.service.OAuthClientService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/oauth/clients")
@RequiredArgsConstructor
public class OAuthClientController {

    private final OAuthClientService clientService;

    @PostMapping("/register")
    public ResponseEntity<?> registerClient(
            @Valid @RequestBody OAuthClientRequest request) {
        OAuthClient client = clientService.registerClient(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(client);
    }
}