// The protected /mcp endpoint: per-grant rate limit, scope gate, then the MCP handler.

import { createMcpHandler, getMcpAuthContext } from "agents/mcp/server";
import type { Env, GrantProps } from "./env";
import { LacrmClient } from "./lacrm";
import { buildServer, canWrite, SCOPE_READ, WRITE_TOOLS } from "./tools";
import { env as workerEnv } from "cloudflare:workers";

const WRITE_SET = new Set<string>(WRITE_TOOLS);

function isGrantProps(p: unknown): p is GrantProps {
  const r = p as GrantProps;
  return !!r && typeof r.apiKey === "string" && Array.isArray(r.scopes) && typeof r.grantId === "string";
}

/** Scopes actually usable: what the user granted, narrowed by what the token carries. */
export function effectiveScopes(granted: readonly string[], tokenScopes?: readonly string[]): string[] {
  const base = granted.filter((s) => s === SCOPE_READ || s === "lacrm.write");
  return tokenScopes ? base.filter((s) => tokenScopes.includes(s)) : base;
}

const mcpHandler = createMcpHandler(
  (reqCtx) => {
    const props = getMcpAuthContext()?.props;
    if (!isGrantProps(props)) throw new Error("missing grant");
    const scopes = effectiveScopes(props.scopes, reqCtx.authInfo?.scopes);
    const client = new LacrmClient({ apiKey: props.apiKey, apiUrl: workerEnv.LACRM_API_URL });
    return buildServer({
      client,
      scopes,
      userId: props.userId,
      log: (m) => console.error(client.clean(m)),
    });
  },
  { route: "/mcp" },
);

function jsonRpc(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...extra } });
}

/** Returns the JSON-RPC ids of tools/call messages that target a write tool. */
export function writeCallIds(body: unknown): { found: boolean; ids: unknown[] } {
  const msgs = Array.isArray(body) ? body : [body];
  const ids: unknown[] = [];
  let found = false;
  for (const m of msgs) {
    if (m && typeof m === "object" && (m as any).method === "tools/call" && WRITE_SET.has(String((m as any).params?.name))) {
      found = true;
      ids.push((m as any).id ?? null);
    }
  }
  return { found, ids };
}

export const mcpApiHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const props = (ctx as unknown as { props?: unknown }).props;
    if (!isGrantProps(props)) return new Response("Unauthorized", { status: 401 });
    const tokenScopes = (ctx as unknown as { auth?: { scope?: string[] } }).auth?.scope;
    const scopes = effectiveScopes(props.scopes, tokenScopes);

    if (request.method === "POST") {
      // 1. Per-grant rate limit, held in a SQLite-backed Durable Object.
      const limit = Math.max(1, Number(env.RATE_LIMIT_PER_MINUTE) || 60);
      const stub = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(props.grantId));
      const decision = await stub.hit(limit);
      if (!decision.ok) {
        return jsonRpc(
          {
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32000,
              message: `Rate limit exceeded: at most ${limit} requests per minute per connection. Retry in ${decision.retryAfterSeconds}s.`,
            },
          },
          429,
          { "Retry-After": String(decision.retryAfterSeconds) },
        );
      }

      // 2. Scope gate on every call, not just tools/list: a read-only grant cannot call a write tool.
      if (!canWrite(scopes)) {
        let body: unknown;
        try {
          body = await request.clone().json();
        } catch {
          body = undefined;
        }
        const { found, ids } = writeCallIds(body);
        if (found) {
          const result = (id: unknown) => ({
            jsonrpc: "2.0",
            id,
            result: {
              content: [
                {
                  type: "text",
                  text: "This connection is read-only (scope lacrm.read). Write tools are disabled; reconnect and choose read and write access to use them.",
                },
              ],
              isError: true,
            },
          });
          return jsonRpc(Array.isArray(body) ? ids.map(result) : result(ids[0]));
        }
      }
    }
    return mcpHandler(request, env, ctx);
  },
};
