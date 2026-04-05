/**
 * @vert/token-auth — In-memory store for testing.
 *
 * NOT for production use. Implements TokenAuthStore with simple Maps.
 */

import type { TokenAuthStore, UserToken, AuthUser } from "./types";

export class InMemoryTokenAuthStore implements TokenAuthStore {
  private tokens = new Map<string, UserToken>();
  private users = new Map<string, AuthUser>();
  private usersByEmail = new Map<string, string>(); // email → userId
  private passwordResetTokens = new Map<string, { userId: string; expiresAt: Date }>();
  private confirmationTokens = new Map<string, { userId: string; expiresAt: Date }>();
  private nextUserId = 1;

  // ─── User Tokens ─────────────────────────────────────────────────────

  async saveToken(token: UserToken): Promise<void> {
    this.tokens.set(token.jti, { ...token });
  }

  async findTokenByJti(jti: string): Promise<UserToken | null> {
    const t = this.tokens.get(jti);
    return t ? { ...t } : null;
  }

  async revokeToken(jti: string): Promise<void> {
    const t = this.tokens.get(jti);
    if (t) {
      t.revokedAt = new Date();
    }
  }

  async revokeTokenFamily(family: string): Promise<number> {
    let count = 0;
    for (const t of this.tokens.values()) {
      if (t.family === family && !t.revokedAt) {
        t.revokedAt = new Date();
        count++;
      }
    }
    return count;
  }

  async revokeAllTokensByUser(userId: string): Promise<number> {
    let count = 0;
    for (const t of this.tokens.values()) {
      if (t.userId === userId && !t.revokedAt) {
        t.revokedAt = new Date();
        count++;
      }
    }
    return count;
  }

  async revokeTokensByUserAndClient(userId: string, clientId: string): Promise<number> {
    let count = 0;
    for (const t of this.tokens.values()) {
      if (t.userId === userId && t.clientId === clientId && !t.revokedAt) {
        t.revokedAt = new Date();
        count++;
      }
    }
    return count;
  }

  async findActiveSessionsByUser(userId: string): Promise<UserToken[]> {
    const result: UserToken[] = [];
    for (const t of this.tokens.values()) {
      if (t.userId === userId) {
        result.push({ ...t });
      }
    }
    return result;
  }

  // ─── User Lookups ────────────────────────────────────────────────────

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const id = this.usersByEmail.get(email.toLowerCase());
    if (!id) return null;
    const u = this.users.get(id);
    return u ? { ...u } : null;
  }

  async findUserById(id: string): Promise<AuthUser | null> {
    const u = this.users.get(id);
    return u ? { ...u } : null;
  }

  async createUser(input: { email: string; passwordHash: string; extras?: Record<string, unknown> }): Promise<AuthUser> {
    const id = String(this.nextUserId++);
    const user: AuthUser = {
      id,
      email: input.email.toLowerCase(),
      passwordHash: input.passwordHash,
      confirmedAt: null,
      lockedAt: null,
      failedAttempts: 0,
    };
    this.users.set(id, user);
    this.usersByEmail.set(user.email, id);
    return { ...user };
  }

  async updateUser(id: string, updates: Partial<Pick<AuthUser, "passwordHash" | "confirmedAt" | "lockedAt" | "failedAttempts">>): Promise<void> {
    const user = this.users.get(id);
    if (!user) return;
    if (updates.passwordHash !== undefined) user.passwordHash = updates.passwordHash;
    if (updates.confirmedAt !== undefined) user.confirmedAt = updates.confirmedAt;
    if (updates.lockedAt !== undefined) user.lockedAt = updates.lockedAt;
    if (updates.failedAttempts !== undefined) user.failedAttempts = updates.failedAttempts;
  }

  // ─── Password Reset ──────────────────────────────────────────────────

  async savePasswordResetToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void> {
    this.passwordResetTokens.set(tokenHash, { userId, expiresAt });
  }

  async findPasswordResetToken(tokenHash: string): Promise<{ userId: string; expiresAt: Date } | null> {
    return this.passwordResetTokens.get(tokenHash) ?? null;
  }

  async deletePasswordResetToken(tokenHash: string): Promise<void> {
    this.passwordResetTokens.delete(tokenHash);
  }

  // ─── Email Confirmation ──────────────────────────────────────────────

  async saveConfirmationToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void> {
    this.confirmationTokens.set(tokenHash, { userId, expiresAt });
  }

  async findConfirmationToken(tokenHash: string): Promise<{ userId: string; expiresAt: Date } | null> {
    return this.confirmationTokens.get(tokenHash) ?? null;
  }

  async deleteConfirmationToken(tokenHash: string): Promise<void> {
    this.confirmationTokens.delete(tokenHash);
  }

  // ─── Test Helpers ────────────────────────────────────────────────────

  clear(): void {
    this.tokens.clear();
    this.users.clear();
    this.usersByEmail.clear();
    this.passwordResetTokens.clear();
    this.confirmationTokens.clear();
    this.nextUserId = 1;
  }
}
