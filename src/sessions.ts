/**
 * @vert/token-auth — Multi-client session management.
 *
 * Supports multiple simultaneous sessions (mobile, web, desktop).
 * Enforces maxSessions limit, revocation by client/user.
 */

import type { TokenAuthConfig, SessionInfo, UserToken } from "./types";
import { maxSessionsReached } from "./errors";

/**
 * List active sessions for a user, grouped by clientId.
 */
export async function listSessions(
  config: TokenAuthConfig,
  userId: string,
): Promise<SessionInfo[]> {
  const tokens = await config.store.findActiveSessionsByUser(userId);
  const now = Date.now();

  // Group by clientId, keep only non-expired, non-revoked refresh tokens
  const byClient = new Map<string, UserToken[]>();
  for (const t of tokens) {
    if (t.revokedAt) continue;
    if (t.expiresAt.getTime() < now) continue;
    if (t.kind !== "refresh") continue;

    const list = byClient.get(t.clientId) ?? [];
    list.push(t);
    byClient.set(t.clientId, list);
  }

  const sessions: SessionInfo[] = [];
  for (const [clientId, clientTokens] of byClient) {
    // Find the earliest created and latest created for this client
    let earliest = clientTokens[0]!;
    let latest = clientTokens[0]!;
    for (const t of clientTokens) {
      if (t.createdAt.getTime() < earliest.createdAt.getTime()) earliest = t;
      if (t.createdAt.getTime() > latest.createdAt.getTime()) latest = t;
    }

    sessions.push({
      clientId,
      createdAt: earliest.createdAt,
      lastActiveAt: latest.createdAt,
      active: true,
    });
  }

  return sessions;
}

/**
 * Count active sessions (distinct client IDs with non-revoked, non-expired refresh tokens).
 */
export async function countActiveSessions(
  config: TokenAuthConfig,
  userId: string,
): Promise<number> {
  const sessions = await listSessions(config, userId);
  return sessions.length;
}

/**
 * Enforce the maxSessions limit before creating a new session.
 * Throws MaxSessionsReached if the limit would be exceeded.
 * Returns true if the check passes.
 */
export async function enforceSessionLimit(
  config: TokenAuthConfig,
  userId: string,
  clientId: string,
): Promise<boolean> {
  const max = config.maxSessions ?? 10;
  if (max <= 0) return true;

  const sessions = await listSessions(config, userId);

  // If this client already has a session, it's a re-login — allow it
  if (sessions.some((s) => s.clientId === clientId)) return true;

  if (sessions.length >= max) {
    throw maxSessionsReached();
  }

  return true;
}

/**
 * Revoke all tokens for a specific client/device.
 */
export async function revokeSession(
  config: TokenAuthConfig,
  userId: string,
  clientId: string,
): Promise<number> {
  return config.store.revokeTokensByUserAndClient(userId, clientId);
}

/**
 * Revoke all sessions for a user.
 */
export async function revokeAllSessions(
  config: TokenAuthConfig,
  userId: string,
): Promise<number> {
  return config.store.revokeAllTokensByUser(userId);
}
