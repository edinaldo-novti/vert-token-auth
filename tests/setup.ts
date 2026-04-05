/**
 * Shared test setup for @vert/token-auth tests.
 *
 * Generates ES256 key pair and creates a default TokenAuthConfig
 * with an InMemoryTokenAuthStore.
 */

import { generateKeyPair } from "jose";
import type { TokenAuthConfig } from "../src/types";
import { InMemoryTokenAuthStore } from "../src/store";

export async function createTestConfig(
  overrides?: Partial<TokenAuthConfig>,
): Promise<TokenAuthConfig & { store: InMemoryTokenAuthStore }> {
  const { publicKey, privateKey } = await generateKeyPair("ES256");

  const store = new InMemoryTokenAuthStore();

  return {
    store,
    signingKey: privateKey,
    verificationKey: publicKey,
    algorithm: "ES256",
    issuer: "test-issuer",
    audience: "test-audience",
    accessTokenTtl: 900,
    refreshTokenTtl: 2_592_000,
    rotateRefreshTokens: true,
    maxSessions: 10,
    ...overrides,
    // Always keep our store unless overridden
    ...(overrides?.store ? {} : { store }),
  } as TokenAuthConfig & { store: InMemoryTokenAuthStore };
}

/**
 * Create a test user with hashed password in the store.
 */
export async function createTestUser(
  store: InMemoryTokenAuthStore,
  email = "test@example.com",
  password = "correct-password",
) {
  const passwordHash = await Bun.password.hash(password, {
    algorithm: "argon2id",
    memoryCost: 19456,
    timeCost: 2,
  });

  return store.createUser({ email, passwordHash });
}
