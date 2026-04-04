# @vert/token-auth

JWT token-based authentication for Bun APIs — inspired by devise_token_auth. Multi-client sessions, refresh token rotation with replay detection, and full auth handler endpoints.

## Installation

```bash
bun add @vert/token-auth
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/sign_in` | Login → returns access + refresh tokens |
| POST | `/auth/sign_up` | Register → returns tokens |
| DELETE | `/auth/sign_out` | Revoke current client tokens |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/password` | Request password reset |
| PUT | `/auth/password` | Confirm password reset |
| GET | `/auth/confirm` | Email confirmation |
| GET | `/auth/validate` | Validate current token |

## Features

- JWT with RS256/ES256/EdDSA (via `jose`)
- Multi-client sessions (mobile, web, desktop simultaneously)
- Refresh token rotation with family-based replay detection
- JWKS endpoint (`/.well-known/jwks.json`)
- Cookie or Bearer token transport

## License

MIT
