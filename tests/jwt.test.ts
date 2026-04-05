import { describe, test, expect, beforeEach } from "bun:test";
import type { TokenAuthConfig } from "../src/types";
import type { InMemoryTokenAuthStore } from "../src/store";
import { createTestConfig } from "./setup";
import {
  generateJti,
  generateFamily,
  signToken,
  verifyToken,
  verifyAndValidateToken,
  issueTokenPair,
  getJwks,
} from "../src/jwt";

let config: TokenAuthConfig & { store: InMemoryTokenAuthStore };

beforeEach(async () => {
  config = await createTestConfig();
});

describe("generateJti", () => {
  test("generates unique URL-safe strings", () => {
    const a = generateJti();
    const b = generateJti();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test("generates strings of approximately expected length", () => {
    // 24 bytes → ~32 base64 chars
    const jti = generateJti(24);
    expect(jti.length).toBeGreaterThanOrEqual(28);
    expect(jti.length).toBeLessThanOrEqual(40);
  });
});

describe("generateFamily", () => {
  test("generates unique family IDs", () => {
    const a = generateFamily();
    const b = generateFamily();
    expect(a).not.toBe(b);
  });
});

describe("signToken", () => {
  test("signs an access token and persists to store", async () => {
    const family = generateFamily();
    const result = await signToken(config, {
      userId: "user-1",
      clientId: "web",
      kind: "access",
      family,
    });

    expect(result.jwt).toBeString();
    expect(result.jti).toBeString();
    expect(result.token.userId).toBe("user-1");
    expect(result.token.clientId).toBe("web");
    expect(result.token.kind).toBe("access");
    expect(result.token.family).toBe(family);
    expect(result.token.revokedAt).toBeNull();

    // Token persisted
    const stored = await config.store.findTokenByJti(result.jti);
    expect(stored).not.toBeNull();
    expect(stored!.jti).toBe(result.jti);
  });

  test("signs a refresh token with previousJti", async () => {
    const family = generateFamily();
    const first = await signToken(config, {
      userId: "user-1",
      clientId: "web",
      kind: "refresh",
      family,
    });

    const second = await signToken(config, {
      userId: "user-1",
      clientId: "web",
      kind: "refresh",
      family,
      previousJti: first.jti,
    });

    expect(second.token.previousJti).toBe(first.jti);
  });

  test("includes custom claims in JWT", async () => {
    const result = await signToken(config, {
      userId: "user-1",
      clientId: "web",
      kind: "access",
      family: generateFamily(),
      customClaims: { role: "admin" },
    });

    const payload = await verifyToken(config, result.jwt);
    expect(payload).not.toBeNull();
    expect((payload as any).role).toBe("admin");
  });
});

describe("verifyToken", () => {
  test("verifies a valid JWT", async () => {
    const result = await signToken(config, {
      userId: "user-1",
      clientId: "web",
      kind: "access",
      family: generateFamily(),
    });

    const payload = await verifyToken(config, result.jwt);
    expect(payload).not.toBeNull();
    expect(payload!.sub).toBe("user-1");
    expect(payload!.cid).toBe("web");
    expect(payload!.kind).toBe("access");
    expect(payload!.jti).toBe(result.jti);
  });

  test("returns null for invalid JWT", async () => {
    const payload = await verifyToken(config, "not-a-jwt");
    expect(payload).toBeNull();
  });

  test("returns null for JWT signed with wrong key", async () => {
    const otherConfig = await createTestConfig();
    const result = await signToken(otherConfig, {
      userId: "user-1",
      clientId: "web",
      kind: "access",
      family: generateFamily(),
    });

    // Verify with original config (different key pair)
    const payload = await verifyToken(config, result.jwt);
    expect(payload).toBeNull();
  });
});

describe("verifyAndValidateToken", () => {
  test("returns payload and record for valid token", async () => {
    const result = await signToken(config, {
      userId: "user-1",
      clientId: "web",
      kind: "access",
      family: generateFamily(),
    });

    const validated = await verifyAndValidateToken(config, result.jwt);
    expect(validated).not.toBeNull();
    expect(validated!.payload.sub).toBe("user-1");
    expect(validated!.record.jti).toBe(result.jti);
  });

  test("returns null for revoked token", async () => {
    const result = await signToken(config, {
      userId: "user-1",
      clientId: "web",
      kind: "access",
      family: generateFamily(),
    });

    await config.store.revokeToken(result.jti);

    const validated = await verifyAndValidateToken(config, result.jwt);
    expect(validated).toBeNull();
  });

  test("filters by expected kind", async () => {
    const result = await signToken(config, {
      userId: "user-1",
      clientId: "web",
      kind: "refresh",
      family: generateFamily(),
    });

    // Expect access, but token is refresh
    const validated = await verifyAndValidateToken(config, result.jwt, "access");
    expect(validated).toBeNull();

    // Correct kind
    const ok = await verifyAndValidateToken(config, result.jwt, "refresh");
    expect(ok).not.toBeNull();
  });
});

describe("issueTokenPair", () => {
  test("issues access + refresh tokens", async () => {
    const pair = await issueTokenPair(config, "user-1", "web");
    expect(pair.accessToken).toBeString();
    expect(pair.refreshToken).toBeString();
    expect(pair.expiresIn).toBe(900);
    expect(pair.tokenType).toBe("Bearer");
    expect(pair.family).toBeString();

    // Both tokens are valid
    const access = await verifyAndValidateToken(config, pair.accessToken, "access");
    expect(access).not.toBeNull();

    const refresh = await verifyAndValidateToken(config, pair.refreshToken, "refresh");
    expect(refresh).not.toBeNull();

    // Same family
    expect(access!.payload.fam).toBe(refresh!.payload.fam);
  });

  test("uses provided family for rotation chain", async () => {
    const fam = generateFamily();
    const pair = await issueTokenPair(config, "user-1", "web", fam, "prev-jti");
    expect(pair.family).toBe(fam);
  });
});

describe("getJwks", () => {
  test("returns a valid JWKS with one key", async () => {
    const jwks = await getJwks(config);
    expect(jwks.keys).toHaveLength(1);
    const key = jwks.keys[0] as any;
    expect(key.alg).toBe("ES256");
    expect(key.use).toBe("sig");
    expect(key.kid).toBeString();
  });
});
