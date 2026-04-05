/**
 * @vert/token-auth — Token refresh strategy.
 *
 * Implements rotation of access+refresh tokens with sliding window
 * and family-based replay detection.
 */

import type { TokenAuthConfig, TokenPair } from "./types";
import { verifyAndValidateToken, issueTokenPair } from "./jwt";
import { tokenInvalid, tokenReplayDetected } from "./errors";

export interface RefreshResult {
  pair: TokenPair & { accessJti: string; refreshJti: string; family: string };
}

/**
 * Refresh an access+refresh token pair.
 *
 * Flow:
 * 1. Verify the refresh JWT and check against the store.
 * 2. If the refresh token is already revoked → replay detected → revoke the entire family.
 * 3. Revoke the used refresh token.
 * 4. Issue a new access+refresh pair in the same family.
 */
export async function refreshTokens(
  config: TokenAuthConfig,
  refreshJwt: string,
): Promise<RefreshResult> {
  // 1. Verify JWT signature and claims
  const result = await verifyAndValidateToken(config, refreshJwt, "refresh");

  if (!result) {
    // Could be an expired or invalid token — try to detect replay
    // by parsing without full validation
    const { verifyToken } = await import("./jwt");
    const payload = await verifyToken(config, refreshJwt);
    if (payload?.fam) {
      // Check if any token in this family exists and is revoked
      const record = payload.jti
        ? await config.store.findTokenByJti(payload.jti)
        : null;
      if (record?.revokedAt) {
        // Replay detected — nuke the whole family
        await config.store.revokeTokenFamily(payload.fam);
        throw tokenReplayDetected();
      }
    }
    throw tokenInvalid();
  }

  const { payload, record } = result;

  // 2. Revoke the used refresh token (one-time use)
  const rotate = config.rotateRefreshTokens ?? true;
  if (rotate) {
    await config.store.revokeToken(record.jti);
  }

  // 3. Issue new pair in the same family
  const pair = await issueTokenPair(
    config,
    payload.sub,
    payload.cid,
    payload.fam,
    record.jti,
  );

  return { pair };
}
