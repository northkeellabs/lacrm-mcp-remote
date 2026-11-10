// "Bring your key, get OAuth": the /authorize consent page.
//
// GET  /authorize  validates the OAuth request (client, exact registered redirect URI,
//                  PKCE, resource) and renders a consent form bound to this browser.
// POST /authorize  checks the CSRF handle, validates the pasted LACRM key with one
//                  GetUser call, then completes the authorization. The key only ever
//                  lives in the grant props, which the provider encrypts.

import {
  AuthorizationError,
  CimdFetchError,
  type ConsentDescription,
  type OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import type { Env, GrantProps } from "./env";
import { LacrmClient, LacrmError } from "./lacrm";
import { escapeHtml as esc } from "./security";
import { SCOPE_READ, SCOPE_WRITE } from "./tools";

const MAX_KEY_LEN = 512;

function nonce(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b));
}

function securityHeaders(n: string, base?: Headers): Headers {
  const h = new Headers(base);
  h.set("Content-Type", "text/html; charset=utf-8");
  // No scripts at all; one nonce'd inline style; no framing. form-action is left out on
  // purpose: browsers apply it to the post-submit redirect to the client's callback.
  h.append(
    "Content-Security-Policy",
    `default-src 'none'; style-src 'nonce-${n}'; img-src 'none'; script-src 'none'; base-uri 'none'; frame-ancestors 'none'`,
  );
  h.set("X-Frame-Options", "DENY");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Cache-Control", "no-store");
  return h;
}

const STYLE = `body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;color:#1b1b1b}
h1{font-size:1.4rem}.box{border:1px solid #ccc;border-radius:6px;padding:.8rem 1rem;margin:1rem 0}
.warn{background:#fff6e0;border-color:#e0b000}.err{background:#fde8e8;border-color:#d33}
label{display:block;margin:.4rem 0}input[type=password]{width:100%;padding:.5rem;font:inherit;box-sizing:border-box}
button{font:inherit;padding:.5rem 1.2rem;margin-right:.6rem}small{color:#555}code{word-break:break-all}`;

function page(title: string, body: string, status = 200, base?: Headers): Response {
  const n = nonce();
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style nonce="${n}">${STYLE}</style></head><body>${body}</body></html>`;
  return new Response(html, { status, headers: securityHeaders(n, base) });
}

export function errorPage(message: string, status = 400): Response {
  return page("Authorization error", `<h1>Authorization could not continue</h1><div class="box err"><p>${esc(message)}</p></div>`, status);
}

export function renderConsent(d: ConsentDescription, handle: string, headers: Headers): Response {
  const name = esc(d.clientName);
  const origin = d.clientDomain
    ? `Published by <strong>${esc(d.clientDomain)}</strong>.`
    : "This app registered itself; its name is not verified.";
  const wantsWrite = d.scope.includes(SCOPE_WRITE);
  const loopback = d.redirectIsLoopback
    ? `<div class="box warn"><strong>This sends access to an app on your computer.</strong> Continue only if you just started connecting from it.</div>`
    : "";
  const body = `<h1>Connect ${name} to Less Annoying CRM?</h1>
<div class="box"><p><strong>${name}</strong> is asking to use your Less Annoying CRM account through this MCP server. ${origin}</p>
<p>Access will be sent to <strong>${esc(d.redirectHost)}</strong><br><small>Redirect URI: <code>${esc(d.redirectUri)}</code></small></p></div>
${loopback}
<form method="post" action="/authorize" autocomplete="off">
<input type="hidden" name="handle" value="${esc(handle)}">
<label for="api_key"><strong>Your LACRM API key</strong> <small>(Settings &gt; Programmer API in Less Annoying CRM)</small></label>
<input type="password" id="api_key" name="api_key" maxlength="${MAX_KEY_LEN}" autocomplete="off" spellcheck="false">
<fieldset class="box"><legend>Access level</legend>
<label><input type="radio" name="access" value="read"${wantsWrite ? "" : " checked"}> Read-only (<code>${SCOPE_READ}</code>): search and read contacts, notes, tasks and pipelines.</label>
<label><input type="radio" name="access" value="write"${wantsWrite ? " checked" : ""}> Read and write (<code>${SCOPE_READ} ${SCOPE_WRITE}</code>): also create contacts, notes and tasks, and move pipeline items between statuses. There are no delete tools.</label>
</fieldset>
<p><small>The key is checked with one read-only call to LACRM, then stored only inside the encrypted grant for this connection; it is never shown to the app. To revoke access at any time, delete or rotate the key in LACRM. This server is independent and unofficial, not affiliated with Less Annoying CRM.</small></p>
<p><button type="submit" name="decision" value="approve">Allow</button><button type="submit" name="decision" value="deny">Deny</button></p>
</form>`;
  return page(`Authorize ${d.clientName}`, body, 200, headers);
}

function handleOAuthError(error: unknown): Response {
  if (error instanceof AuthorizationError && error.redirectTo) {
    return new Response(null, { status: 302, headers: { Location: error.redirectTo } });
  }
  if (error instanceof AuthorizationError) return errorPage(error.description || "Invalid authorization request.");
  if (error instanceof CimdFetchError) return errorPage("This app could not be verified.");
  throw error;
}

/** Validate a pasted LACRM API key with one GetUser call. Returns the LACRM user id. */
export async function validateLacrmKey(apiKey: string, env: Env): Promise<string> {
  const client = new LacrmClient({ apiKey, apiUrl: env.LACRM_API_URL, timeoutMs: 10_000, maxRetries: 1 });
  const user = await client.call("GetUser");
  const id = user && typeof user === "object" ? (user as Record<string, unknown>).UserId : undefined;
  if (id === undefined || id === null || id === "") throw new LacrmError("GetUser: no user id in the response");
  return String(id);
}

export async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  const oauth: OAuthHelpers = env.OAUTH_PROVIDER;
  try {
    if (request.method === "GET") {
      const authReq = await oauth.parseAuthRequest(request); // rejects unknown clients / unregistered redirect URIs
      const details = await oauth.describeConsent(authReq);
      const consent = await oauth.beginConsent(authReq);
      return renderConsent(details, consent.handle, consent.headers);
    }
    if (request.method !== "POST") return errorPage("Method not allowed.", 405);

    const ct = request.headers.get("Content-Type") || "";
    if (!ct.startsWith("application/x-www-form-urlencoded") && !ct.startsWith("multipart/form-data")) {
      return errorPage("Expected a form submission.");
    }
    const form = await request.formData();
    const handle = String(form.get("handle") ?? "");
    // Cheap CSRF pre-check before any outbound call; approveConsent()/denyConsent() then
    // verify the handle against this browser's binding cookie and consume it.
    if (!handle || !(request.headers.get("Cookie") || "").includes("__Host-oauth-consent-")) {
      return errorPage("Missing or invalid CSRF token. Start connecting again from your app.", 403);
    }
    if (form.get("decision") !== "approve") {
      const denied = await oauth.denyConsent(request, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    const access = String(form.get("access") ?? "");
    if (access !== "read" && access !== "write") return errorPage("Choose an access level.");
    const apiKey = String(form.get("api_key") ?? "").trim();
    if (!apiKey || apiKey.length > MAX_KEY_LEN || /\s/.test(apiKey)) {
      return errorPage("Paste your LACRM API key. Press Back in your browser and try again.");
    }

    let userId: string;
    try {
      userId = await validateLacrmKey(apiKey, env);
    } catch (exc) {
      // Never echo the key; the LACRM message is redacted by the client.
      const why = exc instanceof LacrmError ? new LacrmClient({ apiKey }).clean(exc.message) : "unexpected error";
      return errorPage(`Less Annoying CRM did not accept this API key (${why}). Press Back in your browser, check the key and try again.`);
    }

    const scopes = access === "write" ? [SCOPE_READ, SCOPE_WRITE] : [SCOPE_READ];
    const approved = await oauth.approveConsent(request, handle, { scope: scopes });
    const props: GrantProps = { apiKey, userId, scopes, grantId: crypto.randomUUID() };
    const { redirectTo } = await oauth.completeAuthorization({
      request: approved.request,
      userId,
      metadata: { access },
      scope: scopes,
      props,
    });
    approved.headers.set("Location", redirectTo);
    return new Response(null, { status: 302, headers: approved.headers });
  } catch (error) {
    return handleOAuthError(error);
  }
}

export const defaultHandler: ExportedHandler<Env> = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/authorize") return handleAuthorize(request, env);
    if (url.pathname === "/" && request.method === "GET") {
      return page(
        "lacrm-mcp-remote",
        `<h1>lacrm-mcp-remote</h1><p>Unofficial remote MCP server for Less Annoying CRM. Connect an MCP client to <code>${esc(env.MCP_RESOURCE)}</code>.</p><p><small>Independent project, not affiliated with Less Annoying CRM.</small></p>`,
      );
    }
    return new Response("Not found", { status: 404 });
  },
};
