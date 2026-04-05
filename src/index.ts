/**
 * @vert/token-auth — JWT token-based authentication for Bun APIs.
 *
 * Modules: JWT Engine, Multi-Client Sessions, Token Refresh Strategy,
 * API Auth Handlers, Headers & Transport.
 */

export const VERSION = "0.1.0";

// Types
export type {
  TokenKind,
  JwtAlgorithm,
  UserToken,
  TokenPayload,
  TokenPair,
  SessionInfo,
  SignInInput,
  SignUpInput,
  PasswordResetRequestInput,
  PasswordResetConfirmInput,
  AuthUser,
  TokenAuthStore,
  TokenAuthConfig,
} from "./types";

// Errors
export { TokenAuthError } from "./errors";

// JWT Engine
export {
  generateJti,
  generateFamily,
  signToken,
  verifyToken,
  verifyAndValidateToken,
  issueTokenPair,
  getJwks,
} from "./jwt";
export type { SignTokenInput, SignTokenResult } from "./jwt";

// Sessions
export {
  listSessions,
  countActiveSessions,
  enforceSessionLimit,
  revokeSession,
  revokeAllSessions,
} from "./sessions";

// Refresh
export { refreshTokens } from "./refresh";
export type { RefreshResult } from "./refresh";

// Handlers
export {
  signIn,
  signUp,
  signOut,
  signOutAll,
  validateToken,
  requestPasswordReset,
  confirmPasswordReset,
  confirmEmail,
} from "./handlers";
export type { SignInResult, SignUpResult } from "./handlers";

// Middleware
export { requireAuth, optionalAuth, extractBearerToken } from "./middleware";
export type { AuthContext } from "./middleware";

// In-memory store (for testing)
export { InMemoryTokenAuthStore } from "./store";
