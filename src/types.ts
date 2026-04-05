/**
 * @vert/token-auth — Core types.
 */

// ─── Token Types ───────────────────────────────────────────────────────────

export type TokenKind = "access" | "refresh";

export type JwtAlgorithm = "RS256" | "ES256" | "EdDSA";

// ─── User Session Token (persisted) ───────────────────────────────────────

export interface UserToken {
  /** Unique token identifier (JTI). */
  jti: string;
  /** User that owns this token. */
  userId: string;
  /** Client/device identifier (e.g. "web", "mobile-ios", "desktop"). */
  clientId: string;
  /** Whether this is an access or refresh token. */
  kind: TokenKind;
  /** Token family for refresh rotation (shared across rotations). */
  family: string;
  /** Previous JTI in the rotation chain (null for first token). */
  previousJti: string | null;
  /** Expiration timestamp. */
  expiresAt: Date;
  /** Creation timestamp. */
  createdAt: Date;
  /** Revocation timestamp (null if active). */
  revokedAt: Date | null;
}

// ─── JWT Payload (encoded in the token) ───────────────────────────────────

export interface TokenPayload {
  /** Subject — user ID. */
  sub: string;
  /** Token ID. */
  jti: string;
  /** Client/device identifier. */
  cid: string;
  /** Token kind. */
  kind: TokenKind;
  /** Token family. */
  fam: string;
  /** Issued at (unix). */
  iat: number;
  /** Expiration (unix). */
  exp: number;
  /** Issuer. */
  iss?: string;
  /** Audience. */
  aud?: string;
  /** Custom claims. */
  [key: string]: unknown;
}

// ─── Token Pair (returned to the client) ──────────────────────────────────

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  /** Access token expiration in seconds. */
  expiresIn: number;
  tokenType: "Bearer";
}

// ─── Session Info (for listing active sessions) ───────────────────────────

export interface SessionInfo {
  /** Client/device identifier. */
  clientId: string;
  /** Creation time. */
  createdAt: Date;
  /** Last activity (latest token issued for this client). */
  lastActiveAt: Date;
  /** Whether the session is still active. */
  active: boolean;
}

// ─── Credentials Input ───────────────────────────────────────────────────

export interface SignInInput {
  email: string;
  password: string;
  /** Client/device identifier. Default: "default". */
  clientId?: string;
}

export interface SignUpInput {
  email: string;
  password: string;
  /** Client/device identifier. Default: "default". */
  clientId?: string;
  /** Extra fields to pass to the store (name, etc). */
  extras?: Record<string, unknown>;
}

export interface PasswordResetRequestInput {
  email: string;
}

export interface PasswordResetConfirmInput {
  token: string;
  password: string;
}

// ─── Auth User (minimal shape expected by the lib) ────────────────────────

export interface AuthUser {
  id: string;
  email: string;
  passwordHash: string;
  confirmedAt?: Date | null;
  lockedAt?: Date | null;
  failedAttempts?: number;
}

// ─── Store Adapter ────────────────────────────────────────────────────────

/**
 * Pluggable persistence adapter for user tokens and auth operations.
 */
export interface TokenAuthStore {
  // ─── User Tokens ─────────────────────────────────────────────────────
  saveToken(token: UserToken): Promise<void>;
  findTokenByJti(jti: string): Promise<UserToken | null>;
  revokeToken(jti: string): Promise<void>;
  revokeTokenFamily(family: string): Promise<number>;
  revokeAllTokensByUser(userId: string): Promise<number>;
  revokeTokensByUserAndClient(userId: string, clientId: string): Promise<number>;
  findActiveSessionsByUser(userId: string): Promise<UserToken[]>;

  // ─── User Lookups ────────────────────────────────────────────────────
  findUserByEmail(email: string): Promise<AuthUser | null>;
  findUserById(id: string): Promise<AuthUser | null>;
  createUser(input: { email: string; passwordHash: string; extras?: Record<string, unknown> }): Promise<AuthUser>;
  updateUser(id: string, updates: Partial<Pick<AuthUser, "passwordHash" | "confirmedAt" | "lockedAt" | "failedAttempts">>): Promise<void>;

  // ─── Password Reset ──────────────────────────────────────────────────
  savePasswordResetToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void>;
  findPasswordResetToken(tokenHash: string): Promise<{ userId: string; expiresAt: Date } | null>;
  deletePasswordResetToken(tokenHash: string): Promise<void>;

  // ─── Email Confirmation ──────────────────────────────────────────────
  saveConfirmationToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void>;
  findConfirmationToken(tokenHash: string): Promise<{ userId: string; expiresAt: Date } | null>;
  deleteConfirmationToken(tokenHash: string): Promise<void>;
}

// ─── Configuration ────────────────────────────────────────────────────────

export interface TokenAuthConfig {
  /** Persistence adapter. */
  store: TokenAuthStore;

  /** JWT signing key (private key for asymmetric algorithms). */
  signingKey: CryptoKey;

  /** JWT verification key (public key). */
  verificationKey: CryptoKey;

  /** JWT algorithm. Default: "ES256". */
  algorithm?: JwtAlgorithm;

  /** JWT issuer claim. */
  issuer?: string;

  /** JWT audience claim. */
  audience?: string;

  /** Access token lifetime in seconds. Default: 900 (15 min). */
  accessTokenTtl?: number;

  /** Refresh token lifetime in seconds. Default: 2592000 (30 days). */
  refreshTokenTtl?: number;

  /** Whether to rotate refresh tokens on use. Default: true. */
  rotateRefreshTokens?: boolean;

  /** Maximum number of concurrent sessions per user. Default: 10. */
  maxSessions?: number;

  /** Password reset token lifetime in seconds. Default: 3600 (1 hour). */
  passwordResetTtl?: number;

  /** Email confirmation token lifetime in seconds. Default: 86400 (24 hours). */
  confirmationTtl?: number;

  /** Whether email confirmation is required to sign in. Default: false. */
  requireConfirmation?: boolean;

  /** Maximum failed login attempts before lockout. 0 = disabled. Default: 0. */
  maxFailedAttempts?: number;

  /** Lockout duration in seconds. Default: 3600 (1 hour). */
  lockoutDuration?: number;

  /** Callback for sending password reset emails (pluggable). */
  onPasswordResetRequest?: (user: AuthUser, token: string) => Promise<void>;

  /** Callback for sending confirmation emails (pluggable). */
  onConfirmationRequest?: (user: AuthUser, token: string) => Promise<void>;
}
