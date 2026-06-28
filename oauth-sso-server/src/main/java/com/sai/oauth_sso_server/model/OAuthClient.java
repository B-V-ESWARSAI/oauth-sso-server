package com.sai.oauth_sso_server.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "oauth_clients")
@Data
@NoArgsConstructor
public class OAuthClient {

    @Id
    @Column(name = "client_id")
    private String clientId;

    @Column(name = "client_secret", nullable = false)
    private String clientSecret;

    @Column(name = "client_name", nullable = false)
    private String clientName;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_redirect_uris",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "redirect_uri")
    private List<String> redirectUris;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_scopes",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope")
    private List<String> scopes;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_grant_types",
            joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "grant_type")
    private List<String> grantTypes;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}