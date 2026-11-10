#!/usr/bin/env node
// Live end-to-end test against a running `wrangler dev` (default http://localhost:8787).
//
//   LACRM_API_KEY=... node scripts/e2e-live.mjs [baseUrl]
//
// Flow, run twice (read-only grant, then read-write grant):
//   dynamic client registration -> /authorize with PKCE -> consent form with the key from
//   LACRM_API_KEY -> token exchange -> MCP initialize -> tools/list -> tool calls.
// The only write is one add_note on "Maya Demo". Pipeline status is never changed.
// Output is redacted (key, tokens, codes, verifier, CSRF handle) and saved to
// scripts/e2e-live-output.txt.

import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = (process.argv[2] || "http://localhost:8787").replace(/\/$/, "");
const RESOURCE = `${BASE}/mcp`;
const REDIRECT = "http://127.0.0.1:53682/callback";
const KEY = (process.env.LACRM_API_KEY || "").trim();
const OUT = join(dirname(fileURLToPath(import.meta.url)), "e2e-live-output.txt");

const secrets = new Set();
if (KEY) secrets.add(KEY);
const keep = (s) => (s && s.length >= 8 && secrets.add(s), s);
function redact(text) {
  let t = String(text);
  for (const s of [...secrets].sort((a, b) => b.length - a.length)) t = t.split(s).join("[REDACTED]");
  t = t.replace(/(Bearer\s+)(?![a-z_]+=")[A-Za-z0-9._~+/=:-]+/g, "$1[REDACTED]"); // not the realm= challenge
  t = t.replace(/("(?:access_token|refresh_token|code|code_verifier|handle)"\s*:\s*")[^"]+/g, "$1[REDACTED]");
  t = t.replace(/([?&](?:code|code_verifier)=)[^&\s"]+/g, "$1[REDACTED]");
  return t;
}

const lines = [];
const log = (...a) => {
  const line = redact(a.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" "));
  lines.push(line);
  console.log(line);
};
const results = [];
function step(name, pass, detail = "") {
  results.push({ name, pass });
  log(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
  return pass;
}
const b64url = (buf) => Buffer.from(buf).toString("base64url");

function finish(code) {
  const passed = results.filter((r) => r.pass).length;
  log(`\nSUMMARY: ${passed}/${results.length} steps passed`);
  writeFileSync(OUT, redact(lines.join("\n")) + "\n", "utf8");
  process.exit(code);
}

async function readMcp(resp) {
  const ct = resp.headers.get("content-type") || "";
  const text = await resp.text();
  if (ct.includes("text/event-stream")) {
    const data = text
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim())
      .filter(Boolean);
    return data.length ? JSON.parse(data[data.length - 1]) : null;
  }
  return text ? JSON.parse(text) : null;
}

async function authorize(access) {
  // Dynamic client registration (RFC 7591), public client.
  const reg = await fetch(`${BASE}/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: `lacrm-mcp-remote e2e (${access})`,
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    }),
  });
  const client = await reg.json();
  if (!step(`[${access}] dynamic client registration`, reg.status === 201 && !!client.client_id, `HTTP ${reg.status}`)) return null;

  // PKCE S256.
  const verifier = keep(b64url(randomBytes(32)));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const state = b64url(randomBytes(12));
  const scope = access === "write" ? "lacrm.read lacrm.write" : "lacrm.read";
  const authUrl = new URL(`${BASE}/authorize`);
  for (const [k, v] of Object.entries({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: REDIRECT,
    scope,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE,
  }))
    authUrl.searchParams.set(k, v);

  const page = await fetch(authUrl, { redirect: "manual" });
  const html = await page.text();
  const handle = keep(/name="handle" value="([^"]+)"/.exec(html)?.[1] || "");
  const cookies = page.headers.getSetCookie().map((c) => c.split(";")[0]);
  cookies.forEach((c) => keep(c.split("=").slice(1).join("=")));
  const csp = page.headers.get("content-security-policy") || "";
  step(
    `[${access}] GET /authorize renders consent page`,
    page.status === 200 && !!handle && cookies.length > 0 && html.includes(`lacrm-mcp-remote e2e (${access})`) && csp.includes("default-src 'none'"),
    `HTTP ${page.status}, CSP ${csp ? "set" : "missing"}, client name shown: ${html.includes("lacrm-mcp-remote e2e")}`,
  );

  // Consent: submit the form like a browser would, with the key from the environment.
  const form = new URLSearchParams({ handle, api_key: KEY, access, decision: "approve" });
  const post = await fetch(`${BASE}/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookies.join("; ") },
    body: form,
  });
  const loc = post.headers.get("location") || "";
  let code = "";
  let gotState = "";
  try {
    const u = new URL(loc);
    code = keep(u.searchParams.get("code") || "");
    gotState = u.searchParams.get("state") || "";
  } catch {}
  if (!step(`[${access}] consent form accepted, redirect with code`, post.status === 302 && !!code && gotState === state, `HTTP ${post.status}`)) {
    log("  body:", (await post.text()).slice(0, 400));
    return null;
  }

  // Token exchange with the PKCE verifier.
  const tok = await fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      client_id: client.client_id,
      code_verifier: verifier,
      resource: RESOURCE,
    }),
  });
  const tokens = await tok.json();
  keep(tokens.access_token);
  keep(tokens.refresh_token);
  step(
    `[${access}] token exchange`,
    tok.status === 200 && !!tokens.access_token && tokens.token_type?.toLowerCase() === "bearer",
    `HTTP ${tok.status}, scope="${tokens.scope}"`,
  );
  return tokens.access_token ? tokens : null;
}

function mcpClient(token) {
  let id = 0;
  let protocolVersion = "2025-11-25";
  return {
    async rpc(method, params, notify = false) {
      const msg = notify ? { jsonrpc: "2.0", method, params } : { jsonrpc: "2.0", id: ++id, method, params };
      const resp = await fetch(RESOURCE, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          "MCP-Protocol-Version": protocolVersion,
        },
        body: JSON.stringify(msg),
      });
      if (notify) return { status: resp.status };
      const body = await readMcp(resp);
      if (method === "initialize" && body?.result?.protocolVersion) protocolVersion = body.result.protocolVersion;
      return { status: resp.status, body };
    },
  };
}

const toolJson = (r) => {
  try {
    return JSON.parse(r.body?.result?.content?.[0]?.text ?? "null");
  } catch {
    return null;
  }
};

async function runGrant(access) {
  const tokens = await authorize(access);
  if (!tokens) return;
  const mcp = mcpClient(tokens.access_token);

  const init = await mcp.rpc("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "lacrm-mcp-remote-e2e", version: "0.1.0" },
  });
  step(
    `[${access}] MCP initialize`,
    init.status === 200 && init.body?.result?.serverInfo?.name === "lacrm",
    `HTTP ${init.status}, protocol ${init.body?.result?.protocolVersion}, server ${init.body?.result?.serverInfo?.name}`,
  );
  await mcp.rpc("notifications/initialized", {}, true);

  const list = await mcp.rpc("tools/list", {});
  const names = (list.body?.result?.tools || []).map((t) => t.name).sort();
  const want = access === "write" ? 10 : 6;
  step(`[${access}] tools/list returns ${want} tools`, names.length === want, names.join(", "));

  const search = await mcp.rpc("tools/call", { name: "search_contacts", arguments: { query: "Demo" } });
  const found = toolJson(search);
  const shown = (found?.results || []).map((r) => r.name);
  step(
    `[${access}] search_contacts "Demo" finds Maya Demo and Harbour Lane Bakery (Demo)`,
    !search.body?.result?.isError && shown.includes("Maya Demo") && shown.includes("Harbour Lane Bakery (Demo)") && !!found?.data_notice,
    `names: ${JSON.stringify(shown)}, has_more_results=${found?.has_more_results}, data_notice present=${!!found?.data_notice}`,
  );
  const maya = (found?.results || []).find((r) => r.name === "Maya Demo");

  if (access === "read") {
    const attempt = await mcp.rpc("tools/call", {
      name: "add_note",
      arguments: { contact_id: maya?.contact_id || "1", note: "should be refused" },
    });
    const text = attempt.body?.result?.content?.[0]?.text || attempt.body?.error?.message || "";
    step(`[read] write tool add_note is refused`, attempt.body?.result?.isError === true || !!attempt.body?.error, text);
  } else {
    const note = `lacrm-mcp-remote live test ${new Date().toISOString()}`;
    const add = await mcp.rpc("tools/call", { name: "add_note", arguments: { contact_id: maya?.contact_id, note } });
    const res = toolJson(add);
    step(`[write] add_note on Maya Demo`, !add.body?.result?.isError && !!res?.note_id, `note_id=${res?.note_id}, text="${note}"`);
  }
}

async function main() {
  log(`lacrm-mcp-remote live e2e, ${new Date().toISOString()}, base ${BASE}`);
  if (!KEY) {
    step("LACRM_API_KEY present in environment", false, "not set; live test not run");
    finish(2);
  }
  step("LACRM_API_KEY present in environment", true, "value redacted");

  // Discovery: unauthenticated MCP call -> 401 pointing at protected resource metadata.
  const anon = await fetch(RESOURCE, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: "{}",
  });
  const www = anon.headers.get("www-authenticate") || "";
  step("unauthenticated /mcp returns 401 with resource_metadata", anon.status === 401 && www.includes("resource_metadata"), www);
  const prm = await (await fetch(`${BASE}/.well-known/oauth-protected-resource/mcp`)).json().catch(() => ({}));
  step("protected resource metadata (RFC 9728)", prm.resource === RESOURCE, JSON.stringify(prm));
  const asm = await (await fetch(`${BASE}/.well-known/oauth-authorization-server`)).json().catch(() => ({}));
  step(
    "authorization server metadata (RFC 8414): S256, DCR, scopes",
    asm.code_challenge_methods_supported?.includes("S256") && !!asm.registration_endpoint && asm.scopes_supported?.includes("lacrm.write"),
    JSON.stringify({ issuer: asm.issuer, registration_endpoint: asm.registration_endpoint, scopes_supported: asm.scopes_supported }),
  );

  await runGrant("read");
  await runGrant("write");
  finish(results.every((r) => r.pass) ? 0 : 1);
}

main().catch((e) => {
  log("ERROR", e?.stack || String(e));
  finish(1);
});
