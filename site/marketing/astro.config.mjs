import { defineConfig } from "astro/config";

const site = process.env.PUBLIC_SITE_URL || "https://aatuh.github.io";
const base = process.env.PUBLIC_SITE_BASE || "/evydence";

export default defineConfig({
  site,
  base,
  output: "static",
  i18n: {
    defaultLocale: "en",
    locales: ["en", "fi"],
    routing: {
      prefixDefaultLocale: true
    }
  }
});
