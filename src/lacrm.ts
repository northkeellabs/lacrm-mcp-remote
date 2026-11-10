// Minimal client for the LACRM v2 API (POST {"Function", "Parameters"}).
// Port of lacrm_mcp/client.py: same retry policy and error wording.

import { redact } from "./security";

export const LACRM_API_URL = "https://api.lessannoyingcrm.com/v2/";
const MAX_BACKOFF_S = 30;

export class LacrmError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
    readonly retryAfter?: number,
  ) {
    super(message);
    this.name = "LacrmError";
  }
}

export interface LacrmClientOptions {
  apiKey: string;
  apiUrl?: string;
  timeoutMs?: number;
  maxRetries?: number;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
}

function retryAfterSeconds(resp: Response): number | undefined {
  const raw = resp.headers.get("Retry-After");
  if (raw === null) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? Math.max(0, n) : undefined;
}

export class LacrmClient {
  readonly #key: string;
  readonly #url: string;
  readonly #timeoutMs: number;
  readonly #maxRetries: number;
  readonly #fetch: typeof fetch;
  readonly #sleep: (ms: number) => Promise<void>;

  constructor(opts: LacrmClientOptions) {
    this.#key = opts.apiKey;
    this.#url = opts.apiUrl || LACRM_API_URL;
    this.#timeoutMs = opts.timeoutMs ?? 20_000;
    this.#maxRetries = opts.maxRetries ?? 3;
    this.#fetch = opts.fetch ?? ((input, init) => fetch(input, init));
    this.#sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  /** Redact the key (and any Authorization header text) from a message. */
  clean(text: string): string {
    return redact(text, [this.#key]);
  }

  /**
   * Call one API function.
   *
   * 429 is retried for every call (the request was rejected, not processed).
   * 5xx and timeouts are retried only for read calls (idempotent=true), so a
   * write is never silently repeated.
   */
  async call(fn: string, parameters: Record<string, unknown> = {}, idempotent = true): Promise<any> {
    const body = JSON.stringify({ Function: fn, Parameters: parameters });
    let attempt = 0;
    for (;;) {
      let resp: Response;
      try {
        resp = await this.#fetch(this.#url, {
          method: "POST",
          headers: { Authorization: this.#key, "Content-Type": "application/json" },
          body,
          signal: AbortSignal.timeout(this.#timeoutMs),
        });
      } catch (exc) {
        const name = exc instanceof Error ? exc.name : "Error";
        if (name === "TimeoutError" || name === "AbortError") {
          if (idempotent && attempt < this.#maxRetries) {
            await this.#backoff(attempt, undefined);
            attempt++;
            continue;
          }
          throw new LacrmError(`${fn}: request timed out after ${this.#timeoutMs / 1000}s`);
        }
        throw new LacrmError(`${fn}: network error (${name})`);
      }

      if (resp.status === 429) {
        const ra = retryAfterSeconds(resp);
        if (attempt < this.#maxRetries) {
          await this.#backoff(attempt, ra);
          attempt++;
          continue;
        }
        throw new LacrmError(
          `${fn}: rate limited (HTTP 429) after ${attempt} retries.` +
            (ra !== undefined ? ` Server asked to wait ${ra}s.` : ""),
          429,
          undefined,
          ra,
        );
      }
      if (resp.status >= 500) {
        if (idempotent && attempt < this.#maxRetries) {
          await this.#backoff(attempt, retryAfterSeconds(resp));
          attempt++;
          continue;
        }
        throw new LacrmError(`${fn}: LACRM server error (HTTP ${resp.status})`, resp.status);
      }
      return this.#parse(fn, resp);
    }
  }

  async #backoff(attempt: number, retryAfter: number | undefined): Promise<void> {
    const delay = Math.min(retryAfter ?? 0.5 * 2 ** attempt, MAX_BACKOFF_S);
    await this.#sleep(delay * 1000);
  }

  async #parse(fn: string, resp: Response): Promise<any> {
    const text = await resp.text();
    let data: any = undefined;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = undefined;
      }
    }
    if (resp.status === 400) {
      // Docs show the key as "ErrorDecription" (sic); accept both spellings.
      const d = data && typeof data === "object" ? data : {};
      const desc = d.ErrorDescription || d.ErrorDecription || "Bad request";
      const code = d.ErrorCode;
      throw new LacrmError(
        this.clean(`${fn}: LACRM rejected the request${code ? ` (error ${code})` : ""}: ${desc}`),
        400,
        code ? String(code) : undefined,
      );
    }
    if (resp.status === 401 || resp.status === 403) {
      throw new LacrmError(
        `${fn}: not authorised (HTTP ${resp.status}). Check the API key and that it has the needed permissions.`,
        resp.status,
      );
    }
    if (resp.status >= 400) throw new LacrmError(`${fn}: unexpected HTTP ${resp.status}`, resp.status);
    if (!text) return null; // functions that return nothing
    if (data === undefined) throw new LacrmError(`${fn}: response was not valid JSON`);
    return data;
  }
}
