/**
 * @vert/token-auth — Auth middleware.
 *
 * Extracts Bearer token from the Authorization header,
 * verifies it, and injects the authenticated user into the request context.
 */

import type { TokenAuthConfig, AuthUser, TokenPayload } from "./types";
import { verifyAndValidateToken } from "./jwt";
import { unauthorized, tokenInvalid } from "./errors";

export interface AuthContext {
  user: AuthUser;
  payload: TokenPayload;
}

/**
 * Create a requireAuth middleware function.
 *
 * Usage with Bun's built-in server:
 * ```ts
 * const auth = requireAuth(config);
 * // In your handler:
 * const { user, payload } = await auth(request);
 * ```
 */
export function requireAuth(config: TokenAuthConfig) {
  return async (request: Request): Promise<AuthContext> => {
    const header = request.headers.get("authorization");
    if (!header) throw unauthorized();

    const [scheme, token] = header.split(" ", 2);
    if (scheme !== "Bearer" || !token) throw unauthorized();

    const result = await verifyAndValidateToken(config, token, "access");
    if (!result) throw tokenInvalid();

    const user = await config.store.findUserById(result.payload.sub);
    if (!user) throw tokenInvalid();

    return { user, payload: result.payload };
  };
}

/**
 * Extract the Bearer token from a request, or return null.
 */
export function extractBearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const [scheme, token] = header.split(" ", 2);
  if (scheme !== "Bearer" || !token) return null;
  return token;
}

/**
 * Optional auth — tries to authenticate but doesn't throw if no token present.
 * Returns null if no valid token, the AuthContext otherwise.
 */
export function optionalAuth(config: TokenAuthConfig) {
  return async (request: Request): Promise<AuthContext | null> => {
    const token = extractBearerToken(request);
    if (!token) return null;

    const result = await verifyAndValidateToken(config, token, "access");
    if (!result) return null;

    const user = await config.store.findUserById(result.payload.sub);
    if (!user) return null;

    return { user, payload: result.payload };
  };
}
