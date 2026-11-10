import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { RateLimiter } from "./ratelimit";

export interface Env {
  OAUTH_KV: KVNamespace;
  RATE_LIMITER: DurableObjectNamespace<RateLimiter>;
  /** Injected by OAuthProvider into the default handler's env. */
  OAUTH_PROVIDER: OAuthHelpers;
  /** Canonical URL of the MCP endpoint, e.g. https://lacrm-mcp.example.workers.dev/mcp */
  MCP_RESOURCE: string;
  /** Calls per minute per grant. Default 60. */
  RATE_LIMIT_PER_MINUTE?: string;
  /** Override for tests only. */
  LACRM_API_URL?: string;
}

/** What completeAuthorization() stores in the grant. Encrypted at rest by the OAuth provider. */
export interface GrantProps {
  apiKey: string;
  userId: string;
  scopes: string[];
  grantId: string;
}

declare global {
  namespace Cloudflare {
    interface Env {
      OAUTH_KV: KVNamespace;
      RATE_LIMITER: DurableObjectNamespace<RateLimiter>;
      MCP_RESOURCE: string;
      RATE_LIMIT_PER_MINUTE?: string;
      LACRM_API_URL?: string;
    }
  }
}
