/**
 * @vert/token-auth — API auth handlers.
 *
 * Pure functions that implement the auth business logic.
 * Transport-agnostic — they accept inputs and return results,
 * leaving HTTP framework concerns to the caller or middleware.
 */

import type {
  TokenAuthConfig,
  TokenPair,
  SignInInput,
  SignUpInput,
  PasswordResetRequestInput,
  PasswordResetConfirmInput,
  AuthUser,
} from "./types";
import { issueTokenPair, generateJti, verifyAndValidateToken } from "./jwt";
import { enforceSessionLimit, revokeSession, revokeAllSessions } from "./sessions";
import {
  invalidCredentials,
  accountLocked,
  accountNotConfirmed,
  resetTokenInvalid,
  confirmationTokenInvalid,
  tokenInvalid,
} from "./errors";

// ─── Sign In ──────────────────────────────────────────────────────────────

export interface SignInResult {
  user: AuthUser;
  tokens: TokenPair & { accessJti: string; refreshJti: string; family: string };
}

export async function signIn(
  config: TokenAuthConfig,
  input: SignInInput,
): Promise<SignInResult> {
  const { email, password, clientId = "default" } = input;

  const user = await config.store.findUserByEmail(email);
  if (!user) throw invalidCredentials();

  // Check lockout
  const maxAttempts = config.maxFailedAttempts ?? 0;
  if (maxAttempts > 0 && user.lockedAt) {
    const lockoutDuration = (config.lockoutDuration ?? 3600) * 1000;
    if (Date.now() - user.lockedAt.getTime() < lockoutDuration) {
      throw accountLocked();
    }
    // Lock expired — reset
    await config.store.updateUser(user.id, {
      lockedAt: null,
      failedAttempts: 0,
    });
    user.lockedAt = null;
    user.failedAttempts = 0;
  }

  // Verify password
  const valid = await Bun.password.verify(password, user.passwordHash);
  if (!valid) {
    if (maxAttempts > 0) {
      const attempts = (user.failedAttempts ?? 0) + 1;
      const updates: { failedAttempts: number; lockedAt?: Date } = {
        failedAttempts: attempts,
      };
      if (attempts >= maxAttempts) {
        updates.lockedAt = new Date();
      }
      await config.store.updateUser(user.id, updates);
    }
    throw invalidCredentials();
  }

  // Check confirmation
  if (config.requireConfirmation && !user.confirmedAt) {
    throw accountNotConfirmed();
  }

  // Reset failed attempts on successful login
  if (maxAttempts > 0 && (user.failedAttempts ?? 0) > 0) {
    await config.store.updateUser(user.id, { failedAttempts: 0 });
  }

  // Enforce session limit
  await enforceSessionLimit(config, user.id, clientId);

  // Revoke any existing tokens for this client (re-login)
  await revokeSession(config, user.id, clientId);

  // Issue tokens
  const tokens = await issueTokenPair(config, user.id, clientId);

  return { user, tokens };
}

// ─── Sign Up ──────────────────────────────────────────────────────────────

export interface SignUpResult {
  user: AuthUser;
  tokens: TokenPair & { accessJti: string; refreshJti: string; family: string };
  confirmationToken?: string;
}

export async function signUp(
  config: TokenAuthConfig,
  input: SignUpInput,
): Promise<SignUpResult> {
  const { email, password, clientId = "default", extras } = input;

  const passwordHash = await Bun.password.hash(password, {
    algorithm: "argon2id",
    memoryCost: 19456,
    timeCost: 2,
  });

  const user = await config.store.createUser({
    email,
    passwordHash,
    extras,
  });

  let confirmationToken: string | undefined;

  // Send confirmation email if required
  if (config.requireConfirmation && config.onConfirmationRequest) {
    const rawToken = generateJti(32);
    const tokenHash = new Bun.CryptoHasher("sha256")
      .update(rawToken)
      .digest("hex");
    const expiresAt = new Date(
      Date.now() + (config.confirmationTtl ?? 86400) * 1000,
    );
    await config.store.saveConfirmationToken(user.id, tokenHash, expiresAt);
    await config.onConfirmationRequest(user, rawToken);
    confirmationToken = rawToken;
  }

  // Issue tokens (even if confirmation is pending — some APIs allow limited access)
  const tokens = await issueTokenPair(config, user.id, clientId);

  return { user, tokens, confirmationToken };
}

// ─── Sign Out ─────────────────────────────────────────────────────────────

export async function signOut(
  config: TokenAuthConfig,
  accessJwt: string,
): Promise<{ revokedCount: number }> {
  const result = await verifyAndValidateToken(config, accessJwt, "access");
  if (!result) throw tokenInvalid();

  const { payload } = result;
  const count = await revokeSession(config, payload.sub, payload.cid);
  return { revokedCount: count };
}

// ─── Sign Out All ─────────────────────────────────────────────────────────

export async function signOutAll(
  config: TokenAuthConfig,
  accessJwt: string,
): Promise<{ revokedCount: number }> {
  const result = await verifyAndValidateToken(config, accessJwt, "access");
  if (!result) throw tokenInvalid();

  const count = await revokeAllSessions(config, result.payload.sub);
  return { revokedCount: count };
}

// ─── Refresh ──────────────────────────────────────────────────────────────

export { refreshTokens } from "./refresh";

// ─── Validate Token ───────────────────────────────────────────────────────

export async function validateToken(
  config: TokenAuthConfig,
  accessJwt: string,
): Promise<{ user: AuthUser } | null> {
  const result = await verifyAndValidateToken(config, accessJwt, "access");
  if (!result) return null;

  const user = await config.store.findUserById(result.payload.sub);
  if (!user) return null;

  return { user };
}

// ─── Password Reset Request ───────────────────────────────────────────────

export async function requestPasswordReset(
  config: TokenAuthConfig,
  input: PasswordResetRequestInput,
): Promise<void> {
  // Always succeed (don't reveal if user exists)
  const user = await config.store.findUserByEmail(input.email);
  if (!user) return;

  const rawToken = generateJti(32);
  const tokenHash = new Bun.CryptoHasher("sha256")
    .update(rawToken)
    .digest("hex");
  const expiresAt = new Date(
    Date.now() + (config.passwordResetTtl ?? 3600) * 1000,
  );

  await config.store.savePasswordResetToken(user.id, tokenHash, expiresAt);

  if (config.onPasswordResetRequest) {
    await config.onPasswordResetRequest(user, rawToken);
  }
}

// ─── Password Reset Confirm ──────────────────────────────────────────────

export async function confirmPasswordReset(
  config: TokenAuthConfig,
  input: PasswordResetConfirmInput,
): Promise<void> {
  const tokenHash = new Bun.CryptoHasher("sha256")
    .update(input.token)
    .digest("hex");

  const record = await config.store.findPasswordResetToken(tokenHash);
  if (!record) throw resetTokenInvalid();
  if (record.expiresAt.getTime() < Date.now()) {
    await config.store.deletePasswordResetToken(tokenHash);
    throw resetTokenInvalid();
  }

  const passwordHash = await Bun.password.hash(input.password, {
    algorithm: "argon2id",
    memoryCost: 19456,
    timeCost: 2,
  });

  await config.store.updateUser(record.userId, { passwordHash });
  await config.store.deletePasswordResetToken(tokenHash);

  // Revoke all sessions (force re-login with new password)
  await revokeAllSessions(config, record.userId);
}

// ─── Email Confirmation ──────────────────────────────────────────────────

export async function confirmEmail(
  config: TokenAuthConfig,
  rawToken: string,
): Promise<{ userId: string }> {
  const tokenHash = new Bun.CryptoHasher("sha256")
    .update(rawToken)
    .digest("hex");

  const record = await config.store.findConfirmationToken(tokenHash);
  if (!record) throw confirmationTokenInvalid();
  if (record.expiresAt.getTime() < Date.now()) {
    await config.store.deleteConfirmationToken(tokenHash);
    throw confirmationTokenInvalid();
  }

  await config.store.updateUser(record.userId, { confirmedAt: new Date() });
  await config.store.deleteConfirmationToken(tokenHash);

  return { userId: record.userId };
}
