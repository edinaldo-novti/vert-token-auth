import { describe, test, expect, beforeEach } from "bun:test";
import type { TokenAuthConfig } from "../src/types";
import type { InMemoryTokenAuthStore } from "../src/store";
import { createTestConfig, createTestUser } from "./setup";
import { verifyAndValidateToken } from "../src/jwt";
import {
  signIn,
  signUp,
  signOut,
  signOutAll,
  validateToken,
  requestPasswordReset,
  confirmPasswordReset,
  confirmEmail,
} from "../src/handlers";
import { listSessions } from "../src/sessions";

let config: TokenAuthConfig & { store: InMemoryTokenAuthStore };

beforeEach(async () => {
  config = await createTestConfig();
});

// ─── Sign In ──────────────────────────────────────────────────────────────

describe("signIn", () => {
  test("returns user and tokens for valid credentials", async () => {
    await createTestUser(config.store);

    const result = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
    });

    expect(result.user.email).toBe("test@example.com");
    expect(result.tokens.accessToken).toBeString();
    expect(result.tokens.refreshToken).toBeString();
    expect(result.tokens.tokenType).toBe("Bearer");
  });

  test("throws for wrong password", async () => {
    await createTestUser(config.store);

    expect(
      signIn(config, { email: "test@example.com", password: "wrong" }),
    ).rejects.toThrow("Invalid email or password");
  });

  test("throws for non-existent user", async () => {
    expect(
      signIn(config, { email: "nobody@test.com", password: "any" }),
    ).rejects.toThrow("Invalid email or password");
  });

  test("revokes old tokens on re-login to same client", async () => {
    await createTestUser(config.store);

    const first = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
      clientId: "web",
    });

    const second = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
      clientId: "web",
    });

    // Old access token should be revoked
    const oldAccess = await verifyAndValidateToken(config, first.tokens.accessToken, "access");
    expect(oldAccess).toBeNull();

    // New token valid
    const newAccess = await verifyAndValidateToken(config, second.tokens.accessToken, "access");
    expect(newAccess).not.toBeNull();
  });

  test("locks account after max failed attempts", async () => {
    config.maxFailedAttempts = 3;
    await createTestUser(config.store);

    // 3 failed attempts
    for (let i = 0; i < 3; i++) {
      await signIn(config, { email: "test@example.com", password: "wrong" }).catch(() => {});
    }

    // Account now locked
    expect(
      signIn(config, { email: "test@example.com", password: "correct-password" }),
    ).rejects.toThrow("Account is locked");
  });

  test("rejects unconfirmed user when confirmation required", async () => {
    config.requireConfirmation = true;
    await createTestUser(config.store);

    expect(
      signIn(config, { email: "test@example.com", password: "correct-password" }),
    ).rejects.toThrow("Email address has not been confirmed");
  });

  test("allows signs in for confirmed user", async () => {
    config.requireConfirmation = true;
    const user = await createTestUser(config.store);
    await config.store.updateUser(user.id, { confirmedAt: new Date() });

    const result = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
    });
    expect(result.user.id).toBe(user.id);
  });
});

// ─── Sign Up ──────────────────────────────────────────────────────────────

describe("signUp", () => {
  test("creates user and returns tokens", async () => {
    const result = await signUp(config, {
      email: "new@example.com",
      password: "secure-password-123",
    });

    expect(result.user.email).toBe("new@example.com");
    expect(result.tokens.accessToken).toBeString();
    expect(result.tokens.refreshToken).toBeString();

    // User exists in store
    const found = await config.store.findUserByEmail("new@example.com");
    expect(found).not.toBeNull();
  });

  test("sends confirmation email when configured", async () => {
    let sentTo = "";
    let sentToken = "";
    config.requireConfirmation = true;
    config.onConfirmationRequest = async (user, token) => {
      sentTo = user.email;
      sentToken = token;
    };

    const result = await signUp(config, {
      email: "confirm@example.com",
      password: "secure-password-123",
    });

    expect(sentTo).toBe("confirm@example.com");
    expect(sentToken).toBeString();
    expect(result.confirmationToken).toBe(sentToken);
  });
});

// ─── Sign Out ─────────────────────────────────────────────────────────────

describe("signOut", () => {
  test("revokes tokens for the current client", async () => {
    await createTestUser(config.store);
    const { tokens } = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
      clientId: "web",
    });

    const result = await signOut(config, tokens.accessToken);
    expect(result.revokedCount).toBeGreaterThan(0);

    // Token now invalid
    const check = await verifyAndValidateToken(config, tokens.accessToken, "access");
    expect(check).toBeNull();
  });

  test("throws for invalid token", async () => {
    expect(signOut(config, "not-valid")).rejects.toThrow("Token is invalid");
  });
});

// ─── Sign Out All ─────────────────────────────────────────────────────────

describe("signOutAll", () => {
  test("revokes all sessions for the user", async () => {
    await createTestUser(config.store);

    const { tokens: webTokens } = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
      clientId: "web",
    });

    await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
      clientId: "mobile",
    });

    const sessions = await listSessions(config, webTokens.accessJti ? "1" : "1");
    expect(sessions.length).toBeGreaterThanOrEqual(1);

    const result = await signOutAll(config, webTokens.accessToken);
    expect(result.revokedCount).toBeGreaterThan(0);
  });
});

// ─── Validate Token ───────────────────────────────────────────────────────

describe("validateToken", () => {
  test("returns user for valid access token", async () => {
    await createTestUser(config.store);
    const { tokens } = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
    });

    const result = await validateToken(config, tokens.accessToken);
    expect(result).not.toBeNull();
    expect(result!.user.email).toBe("test@example.com");
  });

  test("returns null for invalid token", async () => {
    const result = await validateToken(config, "bad-token");
    expect(result).toBeNull();
  });
});

// ─── Password Reset ──────────────────────────────────────────────────────

describe("password reset", () => {
  test("full flow: request → confirm → old sessions revoked", async () => {
    let resetToken = "";
    config.onPasswordResetRequest = async (_user, token) => {
      resetToken = token;
    };

    await createTestUser(config.store);
    const { tokens } = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
    });

    // Request reset
    await requestPasswordReset(config, { email: "test@example.com" });
    expect(resetToken).toBeString();

    // Confirm reset
    await confirmPasswordReset(config, {
      token: resetToken,
      password: "new-password-456",
    });

    // Old session revoked
    const oldCheck = await verifyAndValidateToken(config, tokens.accessToken, "access");
    expect(oldCheck).toBeNull();

    // New password works
    const result = await signIn(config, {
      email: "test@example.com",
      password: "new-password-456",
    });
    expect(result.user.email).toBe("test@example.com");
  });

  test("does not reveal if user exists", async () => {
    // No user → no error
    await requestPasswordReset(config, { email: "nobody@test.com" });
  });

  test("rejects invalid reset token", async () => {
    expect(
      confirmPasswordReset(config, { token: "bad-token", password: "new" }),
    ).rejects.toThrow("Password reset token is invalid");
  });
});

// ─── Email Confirmation ──────────────────────────────────────────────────

describe("confirmEmail", () => {
  test("confirms user email", async () => {
    let confirmToken = "";
    config.requireConfirmation = true;
    config.onConfirmationRequest = async (_user, token) => {
      confirmToken = token;
    };

    const { user } = await signUp(config, {
      email: "confirm@example.com",
      password: "secure-123",
    });

    expect(confirmToken).toBeString();

    const result = await confirmEmail(config, confirmToken);
    expect(result.userId).toBe(user.id);

    // User is now confirmed
    const updated = await config.store.findUserById(user.id);
    expect(updated!.confirmedAt).not.toBeNull();
  });

  test("rejects invalid confirmation token", async () => {
    expect(confirmEmail(config, "bad-token")).rejects.toThrow(
      "Confirmation token is invalid",
    );
  });
});
