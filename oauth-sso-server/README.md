# 🔐 OAuth 2.0 SSO Server

A production-grade centralized Authentication and Authorization server built from scratch in Java — implementing OAuth 2.0 Authorization Code Flow, JWT (RS256), refresh token rotation, and Single Sign-On (SSO) across multiple client applications.

**[Live API](https://oauth-sso-server-production.up.railway.app)** · **[Swagger Docs](https://oauth-sso-server-production.up.railway.app/swagger-ui/index.html)**

---

## 🎯 What This Is

This is a simplified version of tools like Keycloak, Auth0, or Okta — the same underlying mechanism behind "Login with Google" or "Login with GitHub" buttons you see everywhere.

Any application can redirect users to this server for login. After authentication, the server issues a signed JWT token. Multiple applications can trust tokens issued by this single server — that's **Single Sign-On**: log in once, access every connected app.

To prove this works end-to-end, this repo includes two demo client applications (`student-portal` and `library-system`) that authenticate against this server and share the same login session.

---

## ✨ Features

- **OAuth 2.0 Authorization Code Flow** — the secure, industry-standard flow used by every major OAuth provider
- **Client Credentials Flow** — for machine-to-machine authentication
- **JWT Access Tokens** signed with RS256 (asymmetric RSA keys) — stateless verification, no database lookup needed
- **Refresh Token Rotation** — old tokens are revoked the moment a new one is issued
- **Redis-backed Token Blacklisting** — logout actually works, even with stateless JWTs
- **Single Sign-On (SSO)** — demonstrated live across two separate client applications
- **Role-Based Access Control** — USER / ADMIN roles enforced at the endpoint level
- **Scope-Based Authorization** — OAuth clients are restricted to their registered scopes
- **Token Introspection & JWKS endpoints** — lets any resource server validate tokens independently
- **Full Swagger/OpenAPI documentation** — interactive, testable API docs
- **Unit & integration tests** with Mockito
- **Deployed live** on Railway, connected to managed PostgreSQL (Neon) and Redis Cloud

---

## 🏗️ Architecture

```
┌─────────────────┐         ┌──────────────────────┐
│  Student Portal  │ ──────▶ │                      │
│   (port 8081)    │         │   OAuth 2.0 SSO       │
└─────────────────┘         │   Server (port 8080) │
                             │                      │
┌─────────────────┐         │  • Authorization      │
│  Library System  │ ──────▶ │  • JWT Issuance       │
│   (port 8082)    │         │  • Token Validation   │
└─────────────────┘         └──────────┬───────────┘
                                        │
                          ┌─────────────┴─────────────┐
                          │                            │
                  ┌───────▼────────┐         ┌─────────▼────────┐
                  │  PostgreSQL     │         │  Redis            │
                  │  (Users, OAuth  │         │  (Sessions, Auth   │
                  │   Clients,      │         │   Codes, Token     │
                  │   Refresh Tokens)│        │   Blacklist)       │
                  └─────────────────┘         └────────────────────┘
```

### How SSO Works Here

1. User logs into **Student Portal** → it redirects to the SSO Server's `/oauth/authorize`
2. SSO Server authenticates the user and issues a short-lived, single-use **authorization code**
3. Student Portal exchanges that code for a **JWT access token** + **refresh token**
4. User opens **Library System** in the same session — it also redirects to the SSO Server
5. The same JWT works on Library System too, because both apps trust tokens signed by the same server
6. No second login required — that's SSO

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 4 |
| Security | Spring Security 7, JWT (RS256, `java-jwt`) |
| Database | PostgreSQL (Neon) |
| Cache / Session Store | Redis (Redis Cloud) |
| API Docs | Springdoc OpenAPI / Swagger UI |
| Testing | JUnit 5, Mockito |
| Build Tool | Maven |
| Deployment | Railway |

---

## 📡 API Endpoints

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/auth/register` | Register a new user |
| `POST` | `/auth/login` | Login, returns access + refresh tokens |
| `POST` | `/auth/token/refresh` | Exchange a refresh token for a new token pair |
| `POST` | `/auth/logout` | Blacklist the current access token, revoke refresh tokens |
| `GET` | `/auth/userinfo` | Get the authenticated user's profile |
| `POST` | `/auth/introspect` | Check if a token is valid and inspect its claims |
| `GET` | `/auth/jwks` | Public key (JWK format) for independent token verification |

### OAuth 2.0
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/oauth/authorize` | Authenticate a user and issue an authorization code |
| `POST` | `/oauth/token` | Exchange an authorization code (or client credentials) for tokens |
| `POST` | `/oauth/clients/register` | Register a new OAuth client application |

### Admin (requires `ADMIN` role)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/auth/admin/users` | List all registered users |
| `PUT` | `/auth/admin/users/{id}/roles` | Update a user's roles |

Full interactive documentation: **[Swagger UI](https://oauth-sso-server-production.up.railway.app/swagger-ui/index.html)**

---

## 🚀 Running Locally

### Prerequisites
- Java 21+
- Maven
- A PostgreSQL database (free tier on [Neon](https://neon.tech) works)
- A Redis instance (free tier on [Redis Cloud](https://redis.io/try-free) works)

### Setup

```bash
git clone https://github.com/B-V-ESWARSAI/oauth-sso-server.git
cd oauth-sso-server
```

Set the following environment variables (e.g. in your IDE run configuration):

```
DB_PASSWORD=your_postgres_password
JWT_PRIVATE_KEY=your_base64_rsa_private_key
JWT_PUBLIC_KEY=your_base64_rsa_public_key
REDIS_PASSWORD=your_redis_password
```

> RSA keys can be generated with a 2048-bit `KeyPairGenerator` — see `src/main/java/.../KeyGenerator.java` for a one-off script that prints both keys in Base64.

Update `application.yml` with your own database and Redis host details, then run:

```bash
mvn spring-boot:run
```

The server starts on `http://localhost:8080`. Visit `http://localhost:8080/swagger-ui/index.html` to explore the API.

### Running the SSO Demo Locally

This repo's sibling projects, [`student-portal`](https://github.com/B-V-ESWARSAI/student-portal) and [`library-system`](https://github.com/B-V-ESWARSAI/library-system), demonstrate SSO end-to-end. Run all three simultaneously (ports 8080, 8081, 8082) and log into one to see the same token grant access to the other.

---

## 🧪 Testing

```bash
mvn test
```

Includes unit tests for the authentication service (registration, login, validation failures) and the token service (JWT generation, validation, tamper detection) using Mockito-based mocking.

---

## 🔒 Security Design Notes

- **RS256 over HS256**: tokens are signed with an RSA private key and verified with the corresponding public key. Resource servers only ever need the public key, so they can verify tokens without ever being able to forge one — critical in a multi-service environment.
- **Stateless logout**: JWTs can't be invalidated natively. This server solves that by storing revoked tokens in Redis with a TTL matching the token's remaining lifetime, so the blacklist self-cleans and lookups stay fast.
- **Refresh token rotation**: every time a refresh token is used, it's immediately revoked and replaced. A stolen, already-used refresh token is useless.
- **One-time authorization codes**: codes issued during the OAuth flow are stored in Redis with a 5-minute TTL and deleted the instant they're exchanged, preventing replay.

---

## 📂 Related Repositories

- [`student-portal`](https://github.com/B-V-ESWARSAI/student-portal) — demo client app (SSO consumer)
- [`library-system`](https://github.com/B-V-ESWARSAI/library-system) — second demo client app (SSO consumer)

---

## 👤 Author

**Badham Venkata Eswar Sai**
B.Tech CSE/IT, Mohan Babu University (Class of 2027)

[GitHub](https://github.com/B-V-ESWARSAI) · [LinkedIn](https://linkedin.com/in/badham-e2005)