// Per-grant fixed-window rate limiter, one SQLite-backed Durable Object per grant.

import { DurableObject } from "cloudflare:workers";

export interface RateDecision {
  ok: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

export const WINDOW_MS = 60_000;

export class RateLimiter extends DurableObject {
  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env as never);
    ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS win (id INTEGER PRIMARY KEY CHECK (id = 1), start INTEGER NOT NULL, count INTEGER NOT NULL)",
    );
  }

  /** Count one call; refuse it when the current 60 s window already holds `limit` calls. */
  hit(limit: number, now: number = Date.now()): RateDecision {
    const sql = this.ctx.storage.sql;
    const row = sql.exec<{ start: number; count: number }>("SELECT start, count FROM win WHERE id = 1").toArray()[0];
    let start = row?.start ?? now;
    let count = row?.count ?? 0;
    if (now - start >= WINDOW_MS) {
      start = now;
      count = 0;
    }
    if (count >= limit) {
      return { ok: false, remaining: 0, retryAfterSeconds: Math.max(1, Math.ceil((start + WINDOW_MS - now) / 1000)) };
    }
    count++;
    sql.exec("INSERT OR REPLACE INTO win (id, start, count) VALUES (1, ?, ?)", start, count);
    return { ok: true, remaining: limit - count, retryAfterSeconds: 0 };
  }
}
