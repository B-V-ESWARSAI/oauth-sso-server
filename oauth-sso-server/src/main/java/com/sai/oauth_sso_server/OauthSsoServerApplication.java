package com.sai.oauth_sso_server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity
public class OauthSsoServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(OauthSsoServerApplication.class, args);
    }
}