/**
 * @vert/token-auth — Auth error types.
 */

export class TokenAuthError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode: number = 401,
  ) {
    super(message);
    this.name = "TokenAuthError";
  }

  toJSON() {
    return { error: this.code, message: this.message };
  }
}

export function invalidCredentials(): TokenAuthError {
  return new TokenAuthError("invalid_credentials", "Invalid email or password");
}

export function accountLocked(): TokenAuthError {
  return new TokenAuthError("account_locked", "Account is locked due to too many failed attempts");
}

export function accountNotConfirmed(): TokenAuthError {
  return new TokenAuthError("account_not_confirmed", "Email address has not been confirmed");
}

export function tokenExpired(): TokenAuthError {
  return new TokenAuthError("token_expired", "Token has expired");
}

export function tokenRevoked(): TokenAuthError {
  return new TokenAuthError("token_revoked", "Token has been revoked");
}

export function tokenInvalid(): TokenAuthError {
  return new TokenAuthError("token_invalid", "Token is invalid");
}

export function tokenReplayDetected(): TokenAuthError {
  return new TokenAuthError("token_replay", "Token replay detected — session revoked", 401);
}

export function maxSessionsReached(): TokenAuthError {
  return new TokenAuthError("max_sessions", "Maximum number of concurrent sessions reached", 403);
}

export function resetTokenInvalid(): TokenAuthError {
  return new TokenAuthError("reset_token_invalid", "Password reset token is invalid or expired");
}

export function confirmationTokenInvalid(): TokenAuthError {
  return new TokenAuthError("confirmation_token_invalid", "Confirmation token is invalid or expired");
}

export function unauthorized(): TokenAuthError {
  return new TokenAuthError("unauthorized", "Authentication required");
}
