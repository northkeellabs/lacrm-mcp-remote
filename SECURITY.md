# Security

## What is being protected

A user's LACRM API key (full access to their CRM data within the key's permissions), the CRM data itself, and the integrity of writes made on the user's behalf. The server holds no data of its own beyond OAuth state in KV and a per-grant call counter.

## Threat model

**1. Prompt injection via CRM data.** Notes, names, task descriptions and background info can be written by third parties (a web-form lead, a logged inbound email) and are returned to the model. A hostile note can try to make the model call write tools or leak data. *Mitigations:* every result containing CRM records carries a `data_notice` marking it as untrusted data, not instructions; text fields are truncated at 2,000 characters, lists capped at 50 items and nesting at 8 levels; control characters are stripped. Write tools are narrow (one note, one task, one contact, one status change), there are no delete or bulk tools, pipeline automations are never triggered, and write tools carry `readOnlyHint: false` so clients can ask for approval. Users can grant read-only access, in which case write tools are neither listed nor callable. This reduces exposure but cannot make injected text harmless: keep a human in the loop for writes.

**2. Token theft.** A stolen access token lets an attacker use the grant until it expires. *Mitigations:* access tokens live 1 hour; refresh tokens rotate on use; tokens, refresh tokens and authorization codes are stored only as hashes; tokens are audience-bound to this server's `/mcp` resource (RFC 8707), so a token issued here is not accepted elsewhere and vice versa; PKCE S256 is required for public clients, so an intercepted code is useless without the verifier; only bearer tokens in the `Authorization` header are accepted. Revocation: rotating or deleting the LACRM key makes every grant built on it useless, whoever holds the token, because LACRM then rejects the stored key; the RFC 7009 revocation endpoint is also available to clients.

**3. Consent phishing.** An attacker registers a client called "Claude" and sends a user an authorize link that delivers the grant to the attacker. *Mitigations:* the consent page shows the client name, states when that name is self-asserted (dynamic registration) or shows the verified domain for Client ID Metadata Document clients, always shows the redirect host and full redirect URI, and warns when tokens go to a local app. Redirect URIs must match a registered URI exactly; unknown clients and unregistered redirect URIs are shown as local errors and never redirected to. The page cannot be framed (`frame-ancestors 'none'`, `X-Frame-Options: DENY`), so clickjacking the Allow button is blocked. The form is POST only with a CSRF handle that is bound to the browser by a `__Host-` cookie, works once and expires after 10 minutes, so a cross-site form post cannot complete a grant. Client-supplied strings are HTML-escaped; the CSP forbids all scripts (`script-src 'none'`) and allows one nonce'd inline style.

**4. Key exposure.** *Mitigations:* the key is entered only on the consent page (password field, `autocomplete=off`), sent once to LACRM `GetUser` to validate it, and then stored only inside the OAuth grant props, which the provider encrypts with AES-GCM using key material wrapped by the token, so KV alone does not reveal it. It is never accepted as a tool argument, never included in a tool result, never logged. LACRM error messages are passed through redaction that removes the key value and any `Authorization` header content; unexpected exceptions are reduced to their type name. The consent error page never echoes the submitted key. Tests assert the key does not appear in any response or captured log line. The live test script redacts the key, tokens, codes and the CSRF handle before writing its output.

**5. Abuse and resource exhaustion.** *Mitigations:* per-grant rate limit (60 requests per minute by default) in a SQLite-backed Durable Object, returning HTTP 429 with `Retry-After` and a JSON-RPC error; strict input validation before any outbound call; LACRM 429s retried with bounded backoff; 5xx and timeouts retried only for reads so a write is never silently repeated.

**6. Tool poisoning.** Tool descriptions only describe what each tool does and name the LACRM function it calls. There are no remote-loaded descriptions and no dynamic tool changes beyond the read/write split decided at grant time.

## Operator notes

- `MCP_RESOURCE` must be the exact public URL of `/mcp`; tokens are bound to it.
- Dynamically registered clients expire after 90 days of disuse. Client ID Metadata Document fetches run with `global_fetch_strictly_public` for SSRF protection.
- Grant `userId` (the LACRM user id) and `metadata` (`access: read|write`) are stored unencrypted in KV, as the provider needs them to list and revoke grants. Neither is secret.
- LACRM API keys can be scoped in LACRM. Least privilege applies there too: a read-only key plus a read-only grant is the safest setup for summarising.

## Known limits

- Searches return whatever the API key can see; scope the key, not just the grant.
- Results are not scanned for injection phrases; mitigation is bounding and labelling.
- `get_contact` passes the CRM's custom fields through (truncated).
- Rate limiting is per grant, not per user or IP; an attacker with many grants needs many valid LACRM keys.

## Reporting a vulnerability

Email hello@northkeellabs.com with details. Please do not open a public issue for security reports.
