import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // LACRM is never called for real in unit tests: this host is mocked at fetch().
        bindings: { LACRM_API_URL: "https://lacrm.test/v2/", RATE_LIMIT_PER_MINUTE: "1000" },
      },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
