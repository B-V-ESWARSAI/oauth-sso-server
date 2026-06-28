package com.sai.oauth_sso_server.repository;

import com.sai.oauth_sso_server.model.OAuthClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuthClientRepository extends JpaRepository<OAuthClient, String> {
}