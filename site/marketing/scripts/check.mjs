import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const dist = join(root, "dist");
const configuredBase = process.env.PUBLIC_SITE_BASE ?? "/evydence";
const normalizedBase =
  configuredBase === "/" ? "" : `/${configuredBase.replace(/^\/+|\/+$/g, "")}`;
const withBase = (path) => `${normalizedBase}${path}`.replace(/\/{2,}/g, "/");

const requiredFiles = [
  "index.html",
  "en/index.html",
  "fi/index.html",
  "en/product/index.html",
  "fi/tuote/index.html",
  "en/use-cases/customer-security-review/index.html",
  "fi/kayttotapaukset/asiakkaan-tietoturvakatselmus/index.html",
  "en/use-cases/release-evidence-package/index.html",
  "fi/kayttotapaukset/julkaisun-evidence-paketti/index.html",
  "en/commercial/index.html",
  "fi/kaupallinen/index.html",
  "en/status/index.html",
  "fi/tila/index.html",
  "en/resources/glossary/index.html",
  "fi/resurssit/sanasto/index.html",
  "en/resources/cra-readiness-evidence/index.html",
  "fi/resurssit/cra-valmiuden-evidence/index.html",
  "en/contact/index.html",
  "fi/yhteys/index.html",
  "en/privacy-cookies/index.html",
  "fi/yksityisyys-evasteet/index.html",
  "docs/index.html",
  "github/index.html"
];

for (const file of requiredFiles) {
  const path = join(dist, file);
  if (!existsSync(path)) {
    throw new Error(`missing built page: ${file}`);
  }
}

const rootPage = readFileSync(join(dist, "index.html"), "utf8");
const english = readFileSync(join(dist, "en/index.html"), "utf8");
const finnish = readFileSync(join(dist, "fi/index.html"), "utf8");
const privacy = readFileSync(join(dist, "en/privacy-cookies/index.html"), "utf8");
const cname = readFileSync(join(dist, "CNAME"), "utf8").trim();
const consentSource = readFileSync(join(root, "src/components/ConsentBanner.astro"), "utf8");
const layoutSource = readFileSync(join(root, "src/layouts/BaseLayout.astro"), "utf8");

const requiredRoot = [
  'lang="en"',
  `url=${withBase("/en/")}`,
  "Continue in English",
  withBase("/fi/")
];

for (const text of requiredRoot) {
  if (!rootPage.includes(text)) {
    throw new Error(`Root page missing English default routing marker: ${text}`);
  }
}

if (cname !== "evydence.app") {
  throw new Error(`marketing site CNAME must be evydence.app, got: ${cname}`);
}

const requiredEnglish = [
  'lang="en"',
  'hreflang="fi"',
  "Stop scrambling when customers ask for release security evidence.",
  "https://www.linkedin.com/in/aatu-harju",
  "Cookie preferences",
  "Evydence is not a legal compliance service"
];

for (const text of requiredEnglish) {
  if (!english.includes(text)) {
    throw new Error(`English homepage missing: ${text}`);
  }
}

const requiredFinnish = [
  'lang="fi"',
  'hreflang="en"',
  "Lopeta kiireinen selvittely",
  "Evästeasetukset",
  "Evydence ei ole juridinen"
];

for (const text of requiredFinnish) {
  if (!finnish.includes(text)) {
    throw new Error(`Finnish homepage missing: ${text}`);
  }
}

const consentChecks = [
  "analytics_storage: \"denied\"",
  "ad_storage: \"denied\"",
  "https://www.googletagmanager.com/gtag/js?id=",
  "data-consent-accept-all",
  "data-consent-reject-optional",
  "Accept all",
  "data-cookie-preferences"
];

for (const text of consentChecks) {
  if (!consentSource.includes(text)) {
    throw new Error(`Consent implementation missing: ${text}`);
  }
}

const layoutChecks = [
  "class=\"mobile-nav\"",
  "mobile-nav__panel",
  "font-size: clamp(2.7rem, 5.4vw, 5.25rem)",
  ".hero h1",
  "hyphens: none",
  "word-break: normal",
  ":lang(fi) h2",
  ":lang(fi) .section--split h2",
  "font-size: 1.85rem",
  "overflow-wrap: anywhere",
  ".section--split > *",
  "min-height: min(760px, calc(100vh - 4.8rem))",
  ".nav,\n    .header-actions {\n      display: none;"
];

for (const text of layoutChecks) {
  if (!layoutSource.includes(text)) {
    throw new Error(`Layout implementation missing: ${text}`);
  }
}

for (const forbidden of [
  "innerHTML",
  "Start free trial",
  "100% secure",
  "automatically compliant",
  "mailto:",
  "aatu@example.com"
]) {
  if (english.includes(forbidden) || finnish.includes(forbidden) || privacy.includes(forbidden)) {
    throw new Error(`forbidden site text found: ${forbidden}`);
  }
}

for (const forbidden of ["Accept analytics", "Manage choices", "data-consent-manage"]) {
  if (consentSource.includes(forbidden)) {
    throw new Error(`forbidden consent choice found: ${forbidden}`);
  }
}

console.log("marketing-site-check: passed");
