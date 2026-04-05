import { describe, test, expect } from "bun:test";
import { InMemoryTokenAuthStore } from "../src/store";
import type { UserToken } from "../src/types";

describe("InMemoryTokenAuthStore", () => {
  function makeToken(overrides: Partial<UserToken> = {}): UserToken {
    return {
      jti: "jti-1",
      userId: "user-1",
      clientId: "web",
      kind: "access",
      family: "fam-1",
      previousJti: null,
      expiresAt: new Date(Date.now() + 3600_000),
      createdAt: new Date(),
      revokedAt: null,
      ...overrides,
    };
  }

  // ─── Tokens ──────────────────────────────────────────────────────────

  test("saveToken and findTokenByJti", async () => {
    const store = new InMemoryTokenAuthStore();
    const token = makeToken();
    await store.saveToken(token);

    const found = await store.findTokenByJti("jti-1");
    expect(found).not.toBeNull();
    expect(found!.userId).toBe("user-1");
  });

  test("findTokenByJti returns null for unknown", async () => {
    const store = new InMemoryTokenAuthStore();
    expect(await store.findTokenByJti("nope")).toBeNull();
  });

  test("revokeToken", async () => {
    const store = new InMemoryTokenAuthStore();
    await store.saveToken(makeToken());
    await store.revokeToken("jti-1");

    const found = await store.findTokenByJti("jti-1");
    expect(found!.revokedAt).not.toBeNull();
  });

  test("revokeTokenFamily revokes all in family", async () => {
    const store = new InMemoryTokenAuthStore();
    await store.saveToken(makeToken({ jti: "a", family: "fam-x" }));
    await store.saveToken(makeToken({ jti: "b", family: "fam-x" }));
    await store.saveToken(makeToken({ jti: "c", family: "fam-y" }));

    const count = await store.revokeTokenFamily("fam-x");
    expect(count).toBe(2);

    expect((await store.findTokenByJti("a"))!.revokedAt).not.toBeNull();
    expect((await store.findTokenByJti("b"))!.revokedAt).not.toBeNull();
    expect((await store.findTokenByJti("c"))!.revokedAt).toBeNull();
  });

  test("revokeAllTokensByUser", async () => {
    const store = new InMemoryTokenAuthStore();
    await store.saveToken(makeToken({ jti: "a", userId: "u1" }));
    await store.saveToken(makeToken({ jti: "b", userId: "u1" }));
    await store.saveToken(makeToken({ jti: "c", userId: "u2" }));

    const count = await store.revokeAllTokensByUser("u1");
    expect(count).toBe(2);
  });

  test("revokeTokensByUserAndClient", async () => {
    const store = new InMemoryTokenAuthStore();
    await store.saveToken(makeToken({ jti: "a", userId: "u1", clientId: "web" }));
    await store.saveToken(makeToken({ jti: "b", userId: "u1", clientId: "mobile" }));

    const count = await store.revokeTokensByUserAndClient("u1", "web");
    expect(count).toBe(1);
    expect((await store.findTokenByJti("a"))!.revokedAt).not.toBeNull();
    expect((await store.findTokenByJti("b"))!.revokedAt).toBeNull();
  });

  test("findActiveSessionsByUser returns all user tokens", async () => {
    const store = new InMemoryTokenAuthStore();
    await store.saveToken(makeToken({ jti: "a", userId: "u1" }));
    await store.saveToken(makeToken({ jti: "b", userId: "u1" }));
    await store.saveToken(makeToken({ jti: "c", userId: "u2" }));

    const tokens = await store.findActiveSessionsByUser("u1");
    expect(tokens).toHaveLength(2);
  });

  // ─── Users ───────────────────────────────────────────────────────────

  test("createUser and findUserByEmail", async () => {
    const store = new InMemoryTokenAuthStore();
    const user = await store.createUser({ email: "Test@Example.com", passwordHash: "hash" });

    expect(user.id).toBeString();
    expect(user.email).toBe("test@example.com"); // lowercased

    const found = await store.findUserByEmail("test@example.com");
    expect(found).not.toBeNull();
    expect(found!.id).toBe(user.id);
  });

  test("findUserById", async () => {
    const store = new InMemoryTokenAuthStore();
    const user = await store.createUser({ email: "a@b.com", passwordHash: "h" });

    const found = await store.findUserById(user.id);
    expect(found).not.toBeNull();
    expect(found!.email).toBe("a@b.com");
  });

  test("updateUser applies partial updates", async () => {
    const store = new InMemoryTokenAuthStore();
    const user = await store.createUser({ email: "a@b.com", passwordHash: "old" });

    await store.updateUser(user.id, { passwordHash: "new", failedAttempts: 5 });

    const found = await store.findUserById(user.id);
    expect(found!.passwordHash).toBe("new");
    expect(found!.failedAttempts).toBe(5);
  });

  // ─── Password Reset Tokens ──────────────────────────────────────────

  test("password reset token lifecycle", async () => {
    const store = new InMemoryTokenAuthStore();
    const exp = new Date(Date.now() + 3600_000);

    await store.savePasswordResetToken("u1", "hash-a", exp);
    const found = await store.findPasswordResetToken("hash-a");
    expect(found).not.toBeNull();
    expect(found!.userId).toBe("u1");

    await store.deletePasswordResetToken("hash-a");
    expect(await store.findPasswordResetToken("hash-a")).toBeNull();
  });

  // ─── Confirmation Tokens ────────────────────────────────────────────

  test("confirmation token lifecycle", async () => {
    const store = new InMemoryTokenAuthStore();
    const exp = new Date(Date.now() + 86400_000);

    await store.saveConfirmationToken("u1", "hash-b", exp);
    const found = await store.findConfirmationToken("hash-b");
    expect(found).not.toBeNull();
    expect(found!.userId).toBe("u1");

    await store.deleteConfirmationToken("hash-b");
    expect(await store.findConfirmationToken("hash-b")).toBeNull();
  });

  // ─── Clear ──────────────────────────────────────────────────────────

  test("clear resets all state", async () => {
    const store = new InMemoryTokenAuthStore();
    await store.createUser({ email: "a@b.com", passwordHash: "h" });
    await store.saveToken(makeToken());
    store.clear();

    expect(await store.findUserByEmail("a@b.com")).toBeNull();
    expect(await store.findTokenByJti("jti-1")).toBeNull();
  });
});
