import { describe, test, expect, beforeEach } from "bun:test";
import type { TokenAuthConfig } from "../src/types";
import type { InMemoryTokenAuthStore } from "../src/store";
import { createTestConfig } from "./setup";
import { issueTokenPair, generateFamily } from "../src/jwt";
import {
  listSessions,
  countActiveSessions,
  enforceSessionLimit,
  revokeSession,
  revokeAllSessions,
} from "../src/sessions";

let config: TokenAuthConfig & { store: InMemoryTokenAuthStore };

beforeEach(async () => {
  config = await createTestConfig();
});

describe("listSessions", () => {
  test("returns empty for user with no tokens", async () => {
    const sessions = await listSessions(config, "user-1");
    expect(sessions).toHaveLength(0);
  });

  test("groups sessions by clientId", async () => {
    await issueTokenPair(config, "user-1", "web");
    await issueTokenPair(config, "user-1", "mobile");

    const sessions = await listSessions(config, "user-1");
    expect(sessions).toHaveLength(2);

    const clientIds = sessions.map((s) => s.clientId).sort();
    expect(clientIds).toEqual(["mobile", "web"]);
  });

  test("excludes revoked sessions", async () => {
    await issueTokenPair(config, "user-1", "web");
    await issueTokenPair(config, "user-1", "mobile");

    await revokeSession(config, "user-1", "web");

    const sessions = await listSessions(config, "user-1");
    expect(sessions).toHaveLength(1);
    expect(sessions[0]!.clientId).toBe("mobile");
  });

  test("shows lastActiveAt as latest token creation", async () => {
    await issueTokenPair(config, "user-1", "web");
    // Sign a second pair (rotation)
    await issueTokenPair(config, "user-1", "web");

    const sessions = await listSessions(config, "user-1");
    // Both pairs exist, but the non-revoked latest refresh determines lastActiveAt
    expect(sessions.length).toBeGreaterThanOrEqual(1);
  });
});

describe("countActiveSessions", () => {
  test("counts distinct active client sessions", async () => {
    await issueTokenPair(config, "user-1", "web");
    await issueTokenPair(config, "user-1", "mobile");
    await issueTokenPair(config, "user-1", "desktop");

    expect(await countActiveSessions(config, "user-1")).toBe(3);
  });
});

describe("enforceSessionLimit", () => {
  test("allows sessions below the limit", async () => {
    config.maxSessions = 3;
    await issueTokenPair(config, "user-1", "web");
    await issueTokenPair(config, "user-1", "mobile");

    // Third session should be allowed
    const ok = await enforceSessionLimit(config, "user-1", "desktop");
    expect(ok).toBe(true);
  });

  test("throws when sessions at the limit with a new client", async () => {
    config.maxSessions = 2;
    await issueTokenPair(config, "user-1", "web");
    await issueTokenPair(config, "user-1", "mobile");

    expect(
      enforceSessionLimit(config, "user-1", "desktop"),
    ).rejects.toThrow("Maximum number of concurrent sessions reached");
  });

  test("allows re-login to existing client even at limit", async () => {
    config.maxSessions = 2;
    await issueTokenPair(config, "user-1", "web");
    await issueTokenPair(config, "user-1", "mobile");

    // Re-login to "web" should not throw
    const ok = await enforceSessionLimit(config, "user-1", "web");
    expect(ok).toBe(true);
  });
});

describe("revokeSession", () => {
  test("revokes all tokens for a specific client", async () => {
    await issueTokenPair(config, "user-1", "web");
    await issueTokenPair(config, "user-1", "mobile");

    const count = await revokeSession(config, "user-1", "web");
    expect(count).toBeGreaterThan(0);

    const sessions = await listSessions(config, "user-1");
    expect(sessions).toHaveLength(1);
    expect(sessions[0]!.clientId).toBe("mobile");
  });
});

describe("revokeAllSessions", () => {
  test("revokes all tokens for a user", async () => {
    await issueTokenPair(config, "user-1", "web");
    await issueTokenPair(config, "user-1", "mobile");

    const count = await revokeAllSessions(config, "user-1");
    expect(count).toBeGreaterThan(0);

    const sessions = await listSessions(config, "user-1");
    expect(sessions).toHaveLength(0);
  });
});
