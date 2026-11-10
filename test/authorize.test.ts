import { afterEach, describe, expect, it, vi } from "vitest";
import {
  authorizeUrl,
  BAD_KEY,
  BASE,
  call,
  GOOD_KEY,
  mockLacrm,
  openConsent,
  pkce,
  register,
  submitConsent,
} from "./helpers";

afterEach(() => vi.restoreAllMocks());

describe("GET /authorize", () => {
  it("renders a consent page with client name, redirect host, strict CSP and no scripts", async () => {
    mockLacrm();
    const clientId = await register("Acme Agent");
    const { challenge } = await pkce();
    const { resp, html, handle, cookie } = await openConsent(clientId, challenge);
    expect(resp.status).toBe(200);
    expect(html).toContain("Acme Agent");
    expect(html).toContain("127.0.0.1");
    expect(html).toContain("This sends access to an app on your computer");
    expect(html).toContain("lacrm.read");
    expect(html).toContain("stored only inside the encrypted grant");
    expect(html).toContain("rotate the key in LACRM");
    expect(html).not.toMatch(/<script/i);
    expect(html).toMatch(/<form method="post"/);
    expect(handle).not.toBe("");
    expect(cookie).toContain("__Host-oauth-consent-");
    const csp = resp.headers.get("Content-Security-Policy") || "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(resp.headers.get("X-Frame-Options")).toBe("DENY");
  });

  it("escapes HTML in the client name", async () => {
    mockLacrm();
    const clientId = await register(`<img src=x onerror=alert(1)><script>alert(2)</script>`);
    const { challenge } = await pkce();
    const { html } = await openConsent(clientId, challenge);
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>alert(2)");
    expect(html).toContain("&#60;script&#62;");
  });

  it("rejects a redirect URI that was not registered, without redirecting", async () => {
    const clientId = await register();
    const { challenge } = await pkce();
    const r = await call(new Request(authorizeUrl(clientId, challenge, { redirect: "https://evil.example/cb" }), { redirect: "manual" }));
    expect(r.status).toBe(400);
    expect(r.headers.get("Location")).toBeNull();
    expect(await r.text()).toContain("Authorization could not continue");
  });

  it("rejects an unknown client id", async () => {
    const { challenge } = await pkce();
    const r = await call(new Request(authorizeUrl("no-such-client", challenge), { redirect: "manual" }));
    expect(r.status).toBe(400);
    expect(r.headers.get("Location")).toBeNull();
  });

  it("requires PKCE for public clients", async () => {
    const clientId = await register();
    const u = new URL(authorizeUrl(clientId, "x"));
    u.searchParams.delete("code_challenge");
    u.searchParams.delete("code_challenge_method");
    const r = await call(new Request(u, { redirect: "manual" }));
    expect(r.status === 400 || (r.status === 302 && (r.headers.get("Location") || "").includes("error="))).toBe(true);
  });
});

describe("POST /authorize", () => {
  it("rejects a missing CSRF token", async () => {
    const calls = mockLacrm();
    const clientId = await register();
    const { challenge } = await pkce();
    const { cookie } = await openConsent(clientId, challenge);
    const r = await submitConsent({ api_key: GOOD_KEY, access: "read", decision: "approve" }, cookie);
    expect(r.status).toBe(403);
    expect(r.headers.get("Location")).toBeNull();
    expect(calls).toHaveLength(0); // no outbound call before the CSRF check
  });

  it("rejects a CSRF token without the browser binding cookie", async () => {
    mockLacrm();
    const clientId = await register();
    const { challenge } = await pkce();
    const { handle } = await openConsent(clientId, challenge);
    const r = await submitConsent({ handle, api_key: GOOD_KEY, access: "read", decision: "approve" });
    expect(r.status).toBe(403);
  });

  it("rejects a forged CSRF token even with a cookie", async () => {
    mockLacrm();
    const clientId = await register();
    const { challenge } = await pkce();
    const { cookie } = await openConsent(clientId, challenge);
    const r = await submitConsent({ handle: "forged-handle", api_key: GOOD_KEY, access: "read", decision: "approve" }, cookie);
    expect(r.status).toBe(400);
    expect(r.headers.get("Location")).toBeNull();
  });

  it("rejects a bad LACRM key without echoing it, and leaves the form usable", async () => {
    const calls = mockLacrm();
    const clientId = await register();
    const { challenge } = await pkce();
    const { handle, cookie } = await openConsent(clientId, challenge);
    const r = await submitConsent({ handle, api_key: BAD_KEY, access: "read", decision: "approve" }, cookie);
    const body = await r.text();
    expect(r.status).toBe(400);
    expect(body).toContain("did not accept this API key");
    expect(body).not.toContain(BAD_KEY);
    expect(calls.map((c) => c.fn)).toEqual(["GetUser"]);
    // Back + correct key works with the same handle.
    const ok = await submitConsent({ handle, api_key: GOOD_KEY, access: "read", decision: "approve" }, cookie);
    expect(ok.status).toBe(302);
    expect(ok.headers.get("Location")).toMatch(/^http:\/\/127\.0\.0\.1:53682\/callback\?.*code=/);
  });

  it("rejects an empty key and an invalid access level", async () => {
    mockLacrm();
    const clientId = await register();
    const { challenge } = await pkce();
    const { handle, cookie } = await openConsent(clientId, challenge);
    expect((await submitConsent({ handle, api_key: "", access: "read", decision: "approve" }, cookie)).status).toBe(400);
    expect((await submitConsent({ handle, api_key: GOOD_KEY, access: "admin", decision: "approve" }, cookie)).status).toBe(400);
  });

  it("deny redirects back with access_denied", async () => {
    const calls = mockLacrm();
    const clientId = await register();
    const { challenge } = await pkce();
    const { handle, cookie } = await openConsent(clientId, challenge);
    const r = await submitConsent({ handle, decision: "deny" }, cookie);
    expect(r.status).toBe(302);
    expect(r.headers.get("Location")).toContain("error=access_denied");
    expect(calls).toHaveLength(0);
  });

  it("a handle works only once", async () => {
    mockLacrm();
    const clientId = await register();
    const { challenge } = await pkce();
    const { handle, cookie } = await openConsent(clientId, challenge);
    expect((await submitConsent({ handle, api_key: GOOD_KEY, access: "read", decision: "approve" }, cookie)).status).toBe(302);
    expect((await submitConsent({ handle, api_key: GOOD_KEY, access: "read", decision: "approve" }, cookie)).status).toBe(400);
  });

  it("only accepts POST form bodies", async () => {
    const r = await call(new Request(`${BASE}/authorize`, { method: "PUT" }));
    expect(r.status).toBe(405);
    const j = await call(new Request(`${BASE}/authorize`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }));
    expect(j.status).toBe(400);
  });
});
