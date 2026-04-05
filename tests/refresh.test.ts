import { describe, test, expect, beforeEach } from "bun:test";
import type { TokenAuthConfig } from "../src/types";
import type { InMemoryTokenAuthStore } from "../src/store";
import { createTestConfig } from "./setup";
import { issueTokenPair, verifyAndValidateToken } from "../src/jwt";
import { refreshTokens } from "../src/refresh";

let config: TokenAuthConfig & { store: InMemoryTokenAuthStore };

beforeEach(async () => {
  config = await createTestConfig();
});

describe("refreshTokens", () => {
  test("issues new pair and revokes old refresh token", async () => {
    const original = await issueTokenPair(config, "user-1", "web");

    const { pair } = await refreshTokens(config, original.refreshToken);
    expect(pair.accessToken).toBeString();
    expect(pair.refreshToken).toBeString();
    expect(pair.family).toBe(original.family);

    // Old refresh revoked
    const oldRefresh = await verifyAndValidateToken(config, original.refreshToken, "refresh");
    expect(oldRefresh).toBeNull();

    // New tokens valid
    const newAccess = await verifyAndValidateToken(config, pair.accessToken, "access");
    expect(newAccess).not.toBeNull();

    const newRefresh = await verifyAndValidateToken(config, pair.refreshToken, "refresh");
    expect(newRefresh).not.toBeNull();
  });

  test("preserves family across rotations", async () => {
    const original = await issueTokenPair(config, "user-1", "web");
    const { pair: second } = await refreshTokens(config, original.refreshToken);
    const { pair: third } = await refreshTokens(config, second.refreshToken);

    expect(second.family).toBe(original.family);
    expect(third.family).toBe(original.family);
  });

  test("detects replay and revokes entire family", async () => {
    const original = await issueTokenPair(config, "user-1", "web");

    // First refresh succeeds
    const { pair } = await refreshTokens(config, original.refreshToken);

    // Replay: reuse the same (now revoked) refresh token
    expect(refreshTokens(config, original.refreshToken)).rejects.toThrow(
      "Token replay detected",
    );

    // The new refresh token should also be revoked (entire family)
    const check = await verifyAndValidateToken(config, pair.refreshToken, "refresh");
    expect(check).toBeNull();
  });

  test("fails for invalid JWT", async () => {
    expect(refreshTokens(config, "not-a-jwt")).rejects.toThrow("Token is invalid");
  });

  test("fails for access token (wrong kind)", async () => {
    const pair = await issueTokenPair(config, "user-1", "web");
    expect(refreshTokens(config, pair.accessToken)).rejects.toThrow("Token is invalid");
  });

  test("without rotation, does not revoke old token", async () => {
    config.rotateRefreshTokens = false;
    const original = await issueTokenPair(config, "user-1", "web");

    const { pair } = await refreshTokens(config, original.refreshToken);
    expect(pair.accessToken).toBeString();

    // Old refresh NOT revoked (no rotation)
    const oldRefresh = await verifyAndValidateToken(config, original.refreshToken, "refresh");
    expect(oldRefresh).not.toBeNull();
  });
});
