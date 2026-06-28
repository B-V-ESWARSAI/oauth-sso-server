package com.sai.oauth_sso_server.service;

import com.sai.oauth_sso_server.dto.OAuthClientRequest;
import com.sai.oauth_sso_server.model.OAuthClient;
import com.sai.oauth_sso_server.repository.OAuthClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class OAuthClientService {

    private final OAuthClientRepository clientRepository;

    public OAuthClient registerClient(OAuthClientRequest request) {
        // Check if client ID already exists
        if (clientRepository.existsById(request.getClientId())) {
            throw new IllegalStateException("Client ID already exists");
        }

        OAuthClient client = new OAuthClient();
        client.setClientId(request.getClientId());
        client.setClientSecret(request.getClientSecret());
        client.setClientName(request.getClientName());
        client.setRedirectUris(request.getRedirectUris());
        client.setScopes(request.getScopes());
        client.setGrantTypes(
                request.getGrantTypes() != null
                        ? request.getGrantTypes()
                        : List.of("authorization_code")
        );

        return clientRepository.save(client);
    }

    public OAuthClient getClient(String clientId) {
        return clientRepository.findById(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Client not found: " + clientId));
    }
}