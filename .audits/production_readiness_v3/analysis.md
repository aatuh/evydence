# Marketing Site Production Readiness Audit

Target project: `site/marketing`

Minimum requested score: `8/10`

Audit scope: local marketing-site working tree, related Makefile targets, GitHub Pages workflow, public repository visibility, and passive public-domain reachability. This audit does not remediate findings because the operator requested a pause after the first audit.

Allowed testing boundary: local, non-destructive repository analysis and project-owned checks, plus passive public-state lookups through `gh`, `curl`, and DNS resolution. No live provider settings were changed.

## Latest visible state inspected

Repository: `https://github.com/aatuh/evydence`

Local checkout:

- Branch: `master`
- Local `HEAD`: `c3d4f2a3b451d0091788928af80cec74a3e676e3`
- Local `HEAD` commit date: `2026-06-01T19:52:22+03:00`
- Local `HEAD` subject: `feat(site): add Astro marketing site`
- Working tree: dirty. The audit includes uncommitted marketing-site deployment/contact changes:
  - `.github/workflows/marketing-site-pages.yml`
  - `site/marketing/public/CNAME`
  - `docs/how-to/publish-marketing-site.md`
  - `Makefile`, `README.md`, `docs/README.md`
  - `site/marketing/scripts/check.mjs`
  - `site/marketing/src/data/site.ts`
  - `site/marketing/src/layouts/BaseLayout.astro`
  - `site/marketing/src/templates/MarketingPage.astro`

Public repository state verified with `gh`:

- Public repo: yes
- Archived: no
- Default branch: `master`
- Public default-branch SHA: `c3d4f2a3b451d0091788928af80cec74a3e676e3`
- Public latest release from `gh repo view`: `null`
- Recent public CI: `CI` and `CodeQL` succeeded for `c3d4f2a3b451d0091788928af80cec74a3e676e3` on `2026-06-02`
- Marketing-site Pages workflow public runs: none found

Public domain state:

- `curl -I --max-time 12 https://evydence.app` failed with `Could not resolve host: evydence.app`.
- The public custom domain is not currently reachable from this environment.

Primary language and package evidence:

- Astro static site under `site/marketing`
- `package.json` package: `@evydence/marketing-site@0.1.0`
- Dependency surface: `astro@6.4.2`
- License inherited from repository: `AGPL-3.0-only`

Checks run:

- `npm --prefix site/marketing audit --audit-level=moderate`: passed, `found 0 vulnerabilities`
- `make marketing-site-check`: passed, 23 pages built
- `make marketing-site-production-check`: passed, 23 pages built
- `make docs-check`: passed
- `gh repo view aatuh/evydence ...`: passed
- `gh run list --repo aatuh/evydence --limit 8 ...`: passed
- `gh run list --repo aatuh/evydence --workflow marketing-site-pages.yml ...`: no runs returned
- `curl -I --max-time 12 https://evydence.app`: failed, DNS unresolved

What could not be inspected:

- GitHub Pages repository settings, custom-domain verification, Enforce HTTPS state, and DNS provider configuration.
- Live `https://evydence.app` content, TLS certificate, HTTP redirects, cache behavior, and deployed production artifact.
- Real Google Analytics property configuration, data retention settings, consent-mode reporting behavior, and account access controls.
- Browser-rendered visual/a11y behavior across real device matrix. The audit inspected source and build output but did not run screenshot or Lighthouse checks.

Confidence: medium for local working-tree readiness; low for public production readiness until pending site changes are committed, pushed, deployed, and the domain resolves.

## What the project appears to be

`site/marketing` is a static Astro marketing website for Evydence. It presents Evydence as a self-hosted release evidence ledger for software vendors that need organized technical evidence around releases, SBOMs, vulnerability decisions, customer packages, and compliance-readiness review.

Likely users:

- Product security and AppSec leads
- Platform/release engineering leaders
- Founders or maintainers evaluating self-hosted release evidence workflows
- Commercial/self-hosted buyers

Product shape:

- Static marketing site, not the product runtime.
- English and Finnish localized pages with `/en/` and `/fi/` route prefixes.
- Cookie consent UI with consent-gated Google Analytics.
- GitHub Pages deployment path planned for `evydence.app`.

README and product clarity:

- The repository README communicates the product category quickly.
- The marketing site communicates a sharper buyer problem: answering customer release-security evidence questions.
- The site avoids core prohibited claims: legal compliance, certification, complete SBOMs, authoritative scanner results, and secure-release guarantees.

## Production readiness

Evidence:

- `site/marketing/package.json` has `build`, `check`, `dev`, and `preview` scripts.
- `site/marketing/scripts/check.mjs` validates required pages, language routes, consent-gating markers, CNAME, LinkedIn contact link, forbidden claim text, and mobile/hero CSS guardrails.
- `make marketing-site-check` validates the local `/evydence` base path.
- `make marketing-site-production-check` validates the `https://evydence.app` production build with `PUBLIC_SITE_BASE=/` and `PUBLIC_GA_MEASUREMENT_ID=G-XC2ESEHQ3W`.
- `site/marketing/public/CNAME` contains `evydence.app`.
- `.github/workflows/marketing-site-pages.yml` is present locally with pinned action SHAs, `npm ci`, production build validation, Pages artifact upload, and deployment.
- `docs/how-to/publish-marketing-site.md` documents local dev, production env, Pages settings, DNS, and validation.

Weak points:

- Production deployment is not live: `evydence.app` does not resolve.
- The Pages workflow is uncommitted in the local working tree and has no public run history.
- No screenshot, Lighthouse, accessibility, or responsive visual regression test proves the recently fixed hero/mobile layout across realistic viewports.
- No `robots.txt`, `sitemap.xml`, favicon, or Open Graph image assets were found in the checked site source.
- No deploy-preview workflow or artifact smoke test verifies the uploaded Pages artifact after deployment.

Assessment: good local static-site production candidate, but not yet publicly production-ready because the live domain and Pages run are unverified.

Score: `7/10`

## Feature completeness

Supported use cases:

- Bilingual English/Finnish static site.
- `/en/` and `/fi/` prefixed URLs with English as default.
- Root page redirects users to English.
- Core product, use-case, commercial, status, glossary, CRA-readiness, contact, and privacy/cookie pages.
- Consent banner with `Accept all` and `Reject optional`.
- Google Analytics loading gated behind consent.
- LinkedIn contact path instead of placeholder email.
- GitHub/docs redirect helper pages.
- Production custom-domain build path.

Missing or partial table stakes:

- No sitemap/robots metadata for public discovery.
- No favicon/app icons/OG image for polished public sharing.
- No visual regression or accessibility smoke test.
- No 404 page or explicit not-found behavior check.
- No public deployed proof at `evydence.app`.
- No signed/static artifact checksum for the website deployment artifact.

Maturity classification: controlled marketing-site candidate, not yet a proven production website.

Score: `7.5/10`

## Security and open-source trust

Strong signals:

- Google tags are not loaded directly before consent.
- Build output uses `data-measurement-id` and inline consent logic; Google Tag Manager script is appended only after consent.
- `npm audit --audit-level=moderate` passed with zero vulnerabilities.
- GitHub Pages workflow uses pinned action SHAs rather than floating tags.
- Public product language avoids legal/compliance/security overclaims.
- Contact page warns not to send raw evidence payloads, bearer tokens, private keys, database URLs, customer data, or unreleased package contents through LinkedIn or public contact paths.
- Repository-level `SECURITY.md`, legal/support/governance files, CI, CodeQL, and Scorecard workflows exist outside the site scope.

Weak signals:

- Live deployed behavior could not be inspected.
- No browser-level a11y/security smoke test confirms consent interaction, keyboard behavior, and script loading behavior from a real page.
- No CSP/security-header story for the static deployment. GitHub Pages limits headers, but the limitation should be documented.
- GA property settings, data retention, and consent-mode account configuration are external and unverified.
- The new Pages workflow is local-only at audit time.

Score: `7.5/10`

## Marketability and positioning

Strong signals:

- The site has a concrete buyer question: customer asks whether a CVE in the SBOM affects a release.
- It positions Evydence against scattered scanner exports, CI logs, tickets, and one-off customer answers.
- It keeps the category narrow: release evidence and compliance readiness, not broad GRC or legal compliance automation.
- It includes commercial positioning and contact path.
- English and Finnish support are implemented, which may matter for the maintainer's market and credibility.

Weak signals:

- No live public website yet.
- No screenshots from the actual API/product, demo video, hosted package viewer teaser, or proof artifact preview beyond the stylized dossier visual.
- No customer/adopter quotes or pilot proof.
- Commercial path uses LinkedIn only, which is acceptable for early stage but weaker than a domain-owned contact channel for a commercial product.
- The market category is still emerging and will require sharper proof against DIY release evidence scripts, SBOM platforms, trust centers, and GRC tools.

Score: `7/10`

## Differentiation

Direct alternatives:

- Trust center and customer-security package products
- SBOM inventory and vulnerability management tools
- GRC/control evidence platforms
- Release/security evidence scripts maintained internally

Indirect alternatives:

- Scanner exports plus spreadsheets
- CI artifacts plus ticketing systems
- Customer-specific PDFs maintained manually
- "Do nothing until a customer asks"

Meaningful differentiation:

- Strong product story around release-specific evidence and vulnerability decisions.
- Conservative wording avoids compliance magic.
- Website points reviewers back to GitHub and repository evidence rather than pretending the site is the product.

Weak differentiation:

- The static site alone does not prove the product's deep claims.
- No live demo or concrete artifact walkthrough is surfaced on the marketing site yet.
- Differentiation depends on the repository and product implementation, not the site by itself.

Score: `6.5/10`

## Repository quality checklist

| Area | Status | Evidence | Severity | Recommended fix |
|------|--------|----------|----------|-----------------|
| README | Strong | README has product framing and now points to `https://evydence.app` locally. | Low | Keep website status aligned after deploy. |
| Quickstart | Adequate | Local command exists through `npm --prefix site/marketing run dev`; doc covers publishing. | Low | Add a short marketing-site section to README or keep docs index link prominent. |
| Examples/demo | Adequate | Site pages build; dossier visual exists. | Medium | Add screenshot/demo artifact or route to package viewer/sample evidence. |
| Tests | Adequate | `scripts/check.mjs`, `make marketing-site-check`, `make marketing-site-production-check`. | Medium | Add Playwright/a11y/viewport smoke tests. |
| CI | Partial | Local Pages workflow is present with pinned actions. Public run history absent. | High | Commit/push workflow and verify first successful Pages run. |
| Releases/provenance | Weak for site | No website artifact checksum/provenance distinct from repository release evidence. | Medium | Record Pages artifact or deployment summary for site changes. |
| Docs/API/config/ops | Adequate | `docs/how-to/publish-marketing-site.md` explains domain, DNS, env, and validation. | Low | Add troubleshooting after first deploy. |
| Docker/deployment | N/A | Static GitHub Pages site; no container needed. | N/A | None. |
| Security policy | Strong at repo level, partial for site | Repo policy exists; site consent and sensitive-data warnings exist. | Medium | Document GA property/data-retention and static-hosting header limitations. |
| License/contribution/governance | Strong at repo level | AGPL, governance, support, security files exist. | Low | None for site. |
| Changelog/versioning | Partial for site | Site package version `0.1.0`; no site-specific changelog entry. | Low | Mention site launch in changelog or release notes. |

## Scorecard

| Dimension | Score | Notes |
|-----------|------:|-------|
| Production readiness | 7/10 | Local builds and workflow are credible, but live domain/DNS/Pages run are unverified. |
| Feature completeness | 7.5/10 | Core pages, i18n, consent, GA, contact, docs exist; SEO/social/a11y/visual proof is missing. |
| Security and open-source trust | 7.5/10 | Consent gating, pinned actions, zero npm audit findings, and safe copy are strong; live and browser-level proof is missing. |
| Marketability and positioning | 7/10 | Clear story and conservative claims; no live site, demo proof, or customer evidence yet. |
| Differentiation | 6.5/10 | Good release-evidence positioning, but website alone does not yet prove enough differentiation. |
| Repository evidence quality | 7/10 | Good local checks and docs; pending workflow/domain changes are not public and not deployed. |
| Overall | 7/10 | Promising marketing site candidate, but below the requested 8 until deployment and proof gaps close. |

Calculated mean excluding Overall: `(7 + 7.5 + 7.5 + 7 + 6.5 + 7) / 6 = 7.17/10`.

Overall score: `7/10`.

Confidence: medium for local source readiness; low for public deployed readiness.

Verdict: Promising but not production-ready

Direct answers:

- Mature and high-grade enough for production for most intended uses? Not yet. It is locally credible, but the public domain and Pages workflow are not proven.
- Feature-complete enough to solve a real-world marketing-site problem? Mostly, for an early public site, but missing SEO/social/a11y/visual proof.
- Marketable or interesting enough to attract users, buyers, contributors, or commercial opportunity? Yes, promising, once live and backed by clearer demos/proof.
- Worth continuing, hardening, repositioning, or abandoning? Continue and harden. The next fixes are concrete and small.

## Highest-leverage next steps

### Next 1-2 days

1. Commit and push the Pages workflow, CNAME, GA production build wiring, LinkedIn contact link, and publish guide.
   - Why: local evidence is currently ahead of public evidence.
   - Files: `.github/workflows/marketing-site-pages.yml`, `site/marketing/public/CNAME`, `Makefile`, `docs/how-to/publish-marketing-site.md`, site source files.
   - Improves: CI/deployment trust, public readiness.

2. Configure external DNS and GitHub Pages settings for `evydence.app`.
   - Why: the public domain currently does not resolve.
   - External settings: DNS A/AAAA records, GitHub Pages source, custom domain, Enforce HTTPS.
   - Improves: production readiness.

3. Add sitemap, robots, favicon, and Open Graph image.
   - Why: these are table stakes for a public marketing site.
   - Files: `site/marketing/public/*`, site metadata config.
   - Improves: marketability, repository evidence quality.

4. Add a browser smoke test for consent and responsive layout.
   - Why: source checks do not prove the real browser experience.
   - Files: `site/marketing/scripts/*`, `package.json`, Makefile.
   - Improves: tests, frontend trust.

### Next 1-2 weeks

1. Add a lightweight public demo/proof path from the website.
   - Why: buyers need to see evidence package/release readiness proof quickly.
   - Files: marketing content and routes.
   - Improves: differentiation and marketability.

2. Add post-deploy verification.
   - Why: a successful build is not the same as deployed public behavior.
   - Files: workflow and scripts.
   - Improves: production readiness.

3. Document GA and static-hosting limitations.
   - Why: privacy/security expectations should be explicit.
   - Files: privacy page and publish guide.
   - Improves: security trust.

### Next 1-2 months

1. Add measured, evidence-backed conversion path.
   - Why: LinkedIn is enough for early contact but weak for structured commercial qualification.
   - Files: site content, contact workflow docs, possibly a safer form/provider after review.
   - Improves: commercial adoption.

2. Add website release evidence or deployment manifest.
   - Why: the product sells evidence; the website should model that standard.
   - Files: release/deploy docs or generated manifest.
   - Improves: release integrity.

## README/product-page rewrite advice

Sharper one-sentence pitch:

> Evydence helps software vendors turn release evidence, SBOMs, vulnerability decisions, and build provenance into customer-safe packages that show what was reviewed, what is known, and what remains limited.

Target user:

- Product security lead at a software vendor that repeatedly answers customer release-security reviews.

Core use case to show first:

- A customer asks whether a CVE in a release SBOM affects them; Evydence shows the SBOM, scan finding, VEX/manual decision, approver, evidence links, and customer-safe package.

Best demo/example to surface:

- A static sample release evidence package or local package viewer route linked from the marketing homepage.

Proof points to add:

- Public deployed site with HTTPS.
- Screenshot or short walkthrough of a customer-safe package.
- Verified package/checksum example.
- Clear "what this does not prove" language retained.

What to remove or de-emphasize:

- Avoid generic compliance-readiness phrasing when the concrete customer-CVE workflow can carry the story.
- Avoid implying LinkedIn is a support channel for sensitive evidence.

## Residual risk and uncertainty

- Public `evydence.app` is not live or DNS-resolvable from this environment.
- GitHub Pages settings and Enforce HTTPS could not be verified.
- The local Pages workflow has no public run history at audit time.
- Pending local changes are not yet public repository evidence.
- Real browser layout, keyboard behavior, screen-reader behavior, and Lighthouse performance were not measured.
- GA property settings, data retention, consent-mode account configuration, and access controls remain external.
- No customer/adopter evidence exists for the marketing claim.
- The website is promising but should not be treated as a production-ready public surface until the deployment and proof gaps are closed.
