/**
 * @vert/token-auth — JWT token engine.
 *
 * Generates and verifies JWT access/refresh tokens using jose.
 * Supports RS256, ES256, EdDSA.
 */

import { SignJWT, jwtVerify, exportJWK, calculateJwkThumbprint } from "jose";
import type {
  TokenAuthConfig,
  TokenKind,
  TokenPayload,
  UserToken,
} from "./types";

// ─── Token ID Generation ──────────────────────────────────────────────────

export function generateJti(bytes = 24): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return btoa(String.fromCharCode(...buf))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function generateFamily(): string {
  return generateJti(16);
}

// ─── Sign Token ───────────────────────────────────────────────────────────

export interface SignTokenInput {
  userId: string;
  clientId: string;
  kind: TokenKind;
  family: string;
  previousJti?: string | null;
  customClaims?: Record<string, unknown>;
}

export interface SignTokenResult {
  /** The signed JWT string. */
  jwt: string;
  /** The JTI stored in the token. */
  jti: string;
  /** The persisted token record. */
  token: UserToken;
}

/**
 * Sign a JWT token and persist the token record to the store.
 */
export async function signToken(
  config: TokenAuthConfig,
  input: SignTokenInput,
): Promise<SignTokenResult> {
  const algorithm = config.algorithm ?? "ES256";
  const ttl = input.kind === "access"
    ? (config.accessTokenTtl ?? 900)
    : (config.refreshTokenTtl ?? 2_592_000);

  const jti = generateJti();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttl * 1000);

  // Build JWT
  let builder = new SignJWT({
    cid: input.clientId,
    kind: input.kind,
    fam: input.family,
    ...input.customClaims,
  })
    .setProtectedHeader({ alg: algorithm, typ: "JWT" })
    .setSubject(input.userId)
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(expiresAt);

  if (config.issuer) builder = builder.setIssuer(config.issuer);
  if (config.audience) builder = builder.setAudience(config.audience);

  const jwt = await builder.sign(config.signingKey);

  // Persist token record
  const token: UserToken = {
    jti,
    userId: input.userId,
    clientId: input.clientId,
    kind: input.kind,
    family: input.family,
    previousJti: input.previousJti ?? null,
    expiresAt,
    createdAt: now,
    revokedAt: null,
  };

  await config.store.saveToken(token);

  return { jwt, jti, token };
}

// ─── Verify Token ─────────────────────────────────────────────────────────

/**
 * Verify a JWT and return the decoded payload.
 * Does NOT check revocation — use verifyAndValidateToken for a full check.
 */
export async function verifyToken(
  config: TokenAuthConfig,
  jwt: string,
): Promise<TokenPayload | null> {
  try {
    const algorithm = config.algorithm ?? "ES256";
    const { payload } = await jwtVerify(jwt, config.verificationKey, {
      algorithms: [algorithm],
      issuer: config.issuer,
      audience: config.audience,
    });

    return payload as unknown as TokenPayload;
  } catch {
    return null;
  }
}

/**
 * Verify JWT, check revocation, and check expiration in the store.
 * Returns the token payload and the persisted record.
 */
export async function verifyAndValidateToken(
  config: TokenAuthConfig,
  jwt: string,
  expectedKind?: TokenKind,
): Promise<{ payload: TokenPayload; record: UserToken } | null> {
  const payload = await verifyToken(config, jwt);
  if (!payload) return null;

  // Validate kind if expected
  if (expectedKind && payload.kind !== expectedKind) return null;

  // Check store for revocation
  const record = await config.store.findTokenByJti(payload.jti);
  if (!record) return null;
  if (record.revokedAt) return null;
  if (record.expiresAt.getTime() < Date.now()) return null;

  return { payload, record };
}

// ─── Token Pair ───────────────────────────────────────────────────────────

import type { TokenPair } from "./types";

/**
 * Issue a new access + refresh token pair.
 */
export async function issueTokenPair(
  config: TokenAuthConfig,
  userId: string,
  clientId: string,
  family?: string,
  previousRefreshJti?: string | null,
  customClaims?: Record<string, unknown>,
): Promise<TokenPair & { accessJti: string; refreshJti: string; family: string }> {
  const fam = family ?? generateFamily();

  const access = await signToken(config, {
    userId,
    clientId,
    kind: "access",
    family: fam,
    customClaims,
  });

  const refresh = await signToken(config, {
    userId,
    clientId,
    kind: "refresh",
    family: fam,
    previousJti: previousRefreshJti,
    customClaims,
  });

  return {
    accessToken: access.jwt,
    refreshToken: refresh.jwt,
    expiresIn: config.accessTokenTtl ?? 900,
    tokenType: "Bearer",
    accessJti: access.jti,
    refreshJti: refresh.jti,
    family: fam,
  };
}

// ─── JWKS Endpoint ────────────────────────────────────────────────────────

/**
 * Generate a JWKS response for the public key.
 * Used for `GET /.well-known/jwks.json`.
 */
export async function getJwks(config: TokenAuthConfig): Promise<{ keys: object[] }> {
  const algorithm = config.algorithm ?? "ES256";
  const jwk = await exportJWK(config.verificationKey);
  jwk.alg = algorithm;
  jwk.use = "sig";
  jwk.kid = await calculateJwkThumbprint(jwk);
  return { keys: [jwk] };
}
