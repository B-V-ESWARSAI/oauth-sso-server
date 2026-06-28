package com.sai.oauth_sso_server.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
public class OAuthClientRequest {

    @NotBlank(message = "Client ID is required")
    private String clientId;

    @NotBlank(message = "Client secret is required")
    private String clientSecret;

    @NotBlank(message = "Client name is required")
    private String clientName;

    @NotEmpty(message = "At least one redirect URI is required")
    private List<String> redirectUris;

    @NotEmpty(message = "At least one scope is required")
    private List<String> scopes;

    private List<String> grantTypes;
}