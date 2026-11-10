import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { vi } from "vitest";
import worker from "../src/index";

export const BASE = "http://localhost:8787";
export const RESOURCE = `${BASE}/mcp`;
export const REDIRECT = "http://127.0.0.1:53682/callback";
export const GOOD_KEY = "test-key-GOOD-0123456789abcdef";
export const BAD_KEY = "test-key-BAD-zzzzzzzzzzzzzzzz";
export const LACRM_URL = "https://lacrm.test/v2/";
export const USER_ID = "4137000000000000000000000000001";

export interface LacrmCall {
  fn: string;
  params: Record<string, any>;
  auth: string | null;
}

export type LacrmResponder = (fn: string, params: Record<string, any>) => Response | unknown;

/** Mock the LACRM API at the fetch level. Returns the list of recorded calls. */
export function mockLacrm(responder: LacrmResponder = () => ({})): LacrmCall[] {
  const calls: LacrmCall[] = [];
  const real = globalThis.fetch;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (!url.startsWith(LACRM_URL)) return real(input as any, init);
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body ?? "{}"));
    const call = { fn: body.Function, params: body.Parameters, auth: headers.get("Authorization") };
    calls.push(call);
    if (call.auth !== GOOD_KEY) {
      return new Response(JSON.stringify({ ErrorCode: "InvalidApiKey", ErrorDescription: "Bad key" }), { status: 401 });
    }
    if (call.fn === "GetUser") return Response.json({ UserId: USER_ID, FirstName: "Test" });
    const out = responder(call.fn, call.params);
    return out instanceof Response ? out : Response.json(out ?? null);
  });
  return calls;
}

export async function call(req: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const resp = await worker.fetch(req as any, env as any, ctx);
  await waitOnExecutionContext(ctx);
  return resp;
}

export async function register(name = "Test Client", redirectUris = [REDIRECT]): Promise<string> {
  const r = await call(
    new Request(`${BASE}/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: name,
        redirect_uris: redirectUris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    }),
  );
  if (r.status !== 201) throw new Error(`register failed ${r.status}`);
  return ((await r.json()) as any).client_id;
}

const b64url = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export async function pkce() {
  const v = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const c = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)));
  return { verifier: v, challenge: c };
}

export function authorizeUrl(clientId: string, challenge: string, opts: { redirect?: string; scope?: string; state?: string } = {}) {
  const u = new URL(`${BASE}/authorize`);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", opts.redirect ?? REDIRECT);
  u.searchParams.set("scope", opts.scope ?? "lacrm.read");
  u.searchParams.set("state", opts.state ?? "st4te");
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("resource", RESOURCE);
  return u.toString();
}

export async function openConsent(clientId: string, challenge: string, scope?: string) {
  const r = await call(new Request(authorizeUrl(clientId, challenge, { scope })));
  const html = await r.text();
  const handle = /name="handle" value="([^"]+)"/.exec(html)?.[1] ?? "";
  const cookie = r.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .join("; ");
  return { resp: r, html, handle, cookie };
}

export function submitConsent(fields: Record<string, string>, cookie?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
  if (cookie) headers.Cookie = cookie;
  return call(new Request(`${BASE}/authorize`, { method: "POST", headers, body: new URLSearchParams(fields), redirect: "manual" }));
}

/** Full OAuth flow; returns an access token for a read or write grant. */
export async function getToken(access: "read" | "write" = "read"): Promise<string> {
  const clientId = await register();
  const { verifier, challenge } = await pkce();
  const { handle, cookie } = await openConsent(clientId, challenge, access === "write" ? "lacrm.read lacrm.write" : "lacrm.read");
  const post = await submitConsent({ handle, api_key: GOOD_KEY, access, decision: "approve" }, cookie);
  if (post.status !== 302) throw new Error(`consent failed ${post.status}: ${await post.text()}`);
  const code = new URL(post.headers.get("Location")!).searchParams.get("code")!;
  const tok = await call(
    new Request(`${BASE}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier, resource: RESOURCE }),
    }),
  );
  const t = (await tok.json()) as any;
  if (!t.access_token) throw new Error(`token failed ${tok.status}`);
  return t.access_token;
}

let rpcId = 0;
export async function rpcRaw(token: string, body: unknown): Promise<Response> {
  return call(
    new Request(RESOURCE, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-11-25",
        Host: "localhost:8787", // a real HTTP request always carries one; the MCP handler validates it
      },
      body: JSON.stringify(body),
    }),
  );
}

export async function parseMcp(resp: Response): Promise<any> {
  const text = await resp.text();
  if ((resp.headers.get("content-type") || "").includes("text/event-stream")) {
    const data = text.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim());
    return JSON.parse(data[data.length - 1]);
  }
  return JSON.parse(text);
}

export async function rpc(token: string, method: string, params: unknown = {}): Promise<any> {
  return parseMcp(await rpcRaw(token, { jsonrpc: "2.0", id: ++rpcId, method, params }));
}

export async function callTool(token: string, name: string, args: Record<string, unknown> = {}) {
  const msg = await rpc(token, "tools/call", { name, arguments: args });
  const result = msg.result;
  let json: any = undefined;
  try {
    json = JSON.parse(result?.content?.[0]?.text);
  } catch {}
  return { msg, result, json, text: result?.content?.[0]?.text as string | undefined };
}
