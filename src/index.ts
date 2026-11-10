// lacrm-mcp-remote: unofficial remote MCP server for Less Annoying CRM.
// One Worker that is both the OAuth 2.1 authorization server and the MCP resource server.

import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { env } from "cloudflare:workers";
import { defaultHandler } from "./authorize";
import type { Env } from "./env";
import { mcpApiHandler } from "./mcp";
import { SCOPE_READ, SCOPE_WRITE } from "./tools";

export { RateLimiter } from "./ratelimit";

export default new OAuthProvider<Env>({
  apiRoute: "/mcp",
  apiHandler: mcpApiHandler,
  defaultHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register", // DCR, for clients without CIMD
  clientIdMetadataDocumentEnabled: true,
  scopesSupported: [SCOPE_READ, SCOPE_WRITE],
  requiredScopes: [SCOPE_READ],
  resourceMetadata: {
    resource: env.MCP_RESOURCE,
    resource_name: "Less Annoying CRM (unofficial MCP server)",
  },
  accessTokenTTL: 3600,
});
