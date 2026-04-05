import { describe, test, expect, beforeEach } from "bun:test";
import type { TokenAuthConfig } from "../src/types";
import type { InMemoryTokenAuthStore } from "../src/store";
import { createTestConfig, createTestUser } from "./setup";
import { signIn } from "../src/handlers";
import { requireAuth, optionalAuth, extractBearerToken } from "../src/middleware";

let config: TokenAuthConfig & { store: InMemoryTokenAuthStore };

beforeEach(async () => {
  config = await createTestConfig();
});

function makeRequest(token?: string): Request {
  const headers: Record<string, string> = {};
  if (token) headers["authorization"] = `Bearer ${token}`;
  return new Request("http://localhost/api/test", { headers });
}

describe("extractBearerToken", () => {
  test("extracts token from Authorization header", () => {
    const req = makeRequest("my-token");
    expect(extractBearerToken(req)).toBe("my-token");
  });

  test("returns null without header", () => {
    const req = makeRequest();
    expect(extractBearerToken(req)).toBeNull();
  });

  test("returns null for non-Bearer scheme", () => {
    const req = new Request("http://localhost/", {
      headers: { authorization: "Basic abc123" },
    });
    expect(extractBearerToken(req)).toBeNull();
  });
});

describe("requireAuth", () => {
  test("returns user and payload for valid token", async () => {
    await createTestUser(config.store);
    const { tokens } = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
    });

    const auth = requireAuth(config);
    const result = await auth(makeRequest(tokens.accessToken));
    expect(result.user.email).toBe("test@example.com");
    expect(result.payload.sub).toBe(result.user.id);
  });

  test("throws for missing Authorization header", async () => {
    const auth = requireAuth(config);
    expect(auth(makeRequest())).rejects.toThrow("Authentication required");
  });

  test("throws for invalid token", async () => {
    const auth = requireAuth(config);
    expect(auth(makeRequest("bad-token"))).rejects.toThrow("Token is invalid");
  });

  test("throws for revoked token", async () => {
    await createTestUser(config.store);
    const { tokens } = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
    });

    // Revoke
    await config.store.revokeToken(tokens.accessJti);

    const auth = requireAuth(config);
    expect(auth(makeRequest(tokens.accessToken))).rejects.toThrow("Token is invalid");
  });
});

describe("optionalAuth", () => {
  test("returns AuthContext for valid token", async () => {
    await createTestUser(config.store);
    const { tokens } = await signIn(config, {
      email: "test@example.com",
      password: "correct-password",
    });

    const auth = optionalAuth(config);
    const result = await auth(makeRequest(tokens.accessToken));
    expect(result).not.toBeNull();
    expect(result!.user.email).toBe("test@example.com");
  });

  test("returns null without Authorization header", async () => {
    const auth = optionalAuth(config);
    const result = await auth(makeRequest());
    expect(result).toBeNull();
  });

  test("returns null for invalid token", async () => {
    const auth = optionalAuth(config);
    const result = await auth(makeRequest("bad-token"));
    expect(result).toBeNull();
  });
});
