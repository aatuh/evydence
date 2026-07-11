# Backlog

Project: Evydence marketing site (`site/marketing`)

Status legend:

- [ ] not done
- [x] done
- [e] external dependency, tracked but not implementable inside this repository

Implementation rules for every non-external ticket:

- implement the ticket in the smallest sensible step
- run `make marketing-site-check`, `make marketing-site-production-check`, and `make docs-check` after completing the ticket
- run `npm --prefix site/marketing audit --audit-level=moderate` when dependencies or build tooling change
- create a git commit immediately after the ticket is complete
- use Conventional Commits style for the commit message
- update the ticket checkmark from `[ ]` to `[x]` only after implementation and validation pass
- update the epic checkmark from `[ ]` to `[x]` only when all child tickets are complete
- preserve conservative product language: no legal compliance, certification, complete SBOM, authoritative scanner, or secure-release claims

## Epic E1 - Public Deployment Proof [ ]

Description: Make the marketing site publicly reachable at `evydence.app` and prove the GitHub Pages deployment path works.

### Ticket E1-T1 - Commit and push pending site deployment changes [ ]

Description: Publish the currently local Pages workflow, CNAME, production build target, LinkedIn contact update, and publishing docs so public repository evidence matches local evidence.

Affected readiness dimension: production readiness, repository evidence quality.

Files or behavior to change:

- `.github/workflows/marketing-site-pages.yml`
- `site/marketing/public/CNAME`
- `Makefile`
- `README.md`
- `docs/README.md`
- `docs/how-to/publish-marketing-site.md`
- `site/marketing/**`

Implementation scope:

- stage and commit only the intended source/docs/workflow files
- do not commit generated `site/marketing/dist`, `.astro`, or `node_modules`

Validation or proof:

- `make marketing-site-check`
- `make marketing-site-production-check`
- `make docs-check`
- `git status --short`

Expected score impact: `+0.4` to `+0.6`.

Fix type: release process, CI/security workflow, documentation.

Implementation rules:

- implement the ticket in the smallest sensible step
- run the validation commands listed above
- create a Conventional Commit immediately after the ticket is complete
- update this ticket to `[x]` only after checks and commit pass

### Ticket E1-T2 - Configure DNS and GitHub Pages custom domain [e]

Description: Configure external DNS and repository Pages settings so `https://evydence.app` resolves to the deployed GitHub Pages artifact.

Affected readiness dimension: production readiness, marketability.

Files or behavior to change:

- DNS provider A/AAAA records for `evydence.app`
- optional `www.evydence.app` CNAME
- GitHub repository Pages source set to GitHub Actions
- GitHub Pages custom domain set to `evydence.app`
- Enforce HTTPS enabled after certificate provisioning

Implementation scope:

- external provider/account work; cannot be completed from repository source alone

Validation or proof:

- `dig +short evydence.app A`
- `dig +short evydence.app AAAA`
- `curl -I https://evydence.app`
- GitHub Pages settings screenshot or successful Pages deployment run

Expected score impact: `+0.7` to `+1.0`.

Fix type: external provider setting, deployment/ops evidence.

Implementation rules:

- do not mark done in this repository until the domain resolves and HTTPS works
- record the successful verification command output in a follow-up audit or deployment note

### Ticket E1-T3 - Add post-deploy verification command [ ]

Description: Add a repository-owned check that verifies the live site after deployment without mutating provider state.

Affected readiness dimension: production readiness, CI, repository evidence quality.

Files or behavior to change:

- `Makefile`
- `site/marketing/scripts/`
- `docs/how-to/publish-marketing-site.md`

Implementation scope:

- add a script such as `scripts/check_live_site.mjs` or `site/marketing/scripts/live-check.mjs`
- verify `https://evydence.app/en/`, `/fi/`, `/CNAME`-equivalent domain behavior where possible, canonical URLs, and absence of direct pre-consent Google script tags
- keep failures clear when DNS is unresolved

Validation or proof:

- local dry-run against a configurable `MARKETING_SITE_LIVE_URL`
- successful run after E1-T2 is complete

Expected score impact: `+0.3` to `+0.5`.

Fix type: deployment/ops evidence, tests.

Implementation rules:

- implement the ticket in the smallest sensible step
- avoid active or destructive external tests
- run `make marketing-site-check`, `make marketing-site-production-check`, and `make docs-check`
- create a Conventional Commit immediately after the ticket is complete

## Epic E2 - Public Website Table Stakes [ ]

Description: Add the metadata, discoverability, and public polish expected from a production public marketing site.

### Ticket E2-T1 - Add sitemap and robots files [ ]

Description: Generate or maintain `sitemap.xml` and `robots.txt` for the production site, using `https://evydence.app` and the language-prefixed routes.

Affected readiness dimension: feature completeness, marketability, repository evidence quality.

Files or behavior to change:

- `site/marketing/public/robots.txt`
- generated or checked `site/marketing/public/sitemap.xml`, or a build script that emits it
- `site/marketing/scripts/check.mjs`

Implementation scope:

- include all public English and Finnish pages
- keep `/en/` as the default canonical user path
- avoid indexing helper pages if they are only redirects

Validation or proof:

- `make marketing-site-production-check`
- check that the production `dist` contains `robots.txt` and `sitemap.xml`

Expected score impact: `+0.2` to `+0.4`.

Fix type: implementation, documentation, SEO/marketing readiness.

Implementation rules:

- implement the ticket in the smallest sensible step
- update the checker to fail if files are missing or contain the wrong domain
- create a Conventional Commit immediately after validation passes

### Ticket E2-T2 - Add favicon, app icons, and Open Graph image [ ]

Description: Add minimal branded assets so browser tabs, social previews, and saved links look intentional.

Affected readiness dimension: marketability and positioning, repository evidence quality.

Files or behavior to change:

- `site/marketing/public/favicon.svg` or equivalent icon files
- `site/marketing/public/og-image.*`
- `site/marketing/src/layouts/BaseLayout.astro`
- `site/marketing/scripts/check.mjs`

Implementation scope:

- keep visuals conservative and avoid shield/lock imagery that implies security guarantees
- add Open Graph/Twitter card metadata using the production URL

Validation or proof:

- `make marketing-site-production-check`
- inspect generated `dist/en/index.html` metadata

Expected score impact: `+0.2` to `+0.4`.

Fix type: implementation, public polish.

Implementation rules:

- use repo-native assets or generated bitmap only if appropriate
- update checks so assets and metadata cannot silently disappear
- create a Conventional Commit after validation passes

### Ticket E2-T3 - Add a custom 404 page [ ]

Description: Provide a localized, claim-safe not-found experience for broken public routes.

Affected readiness dimension: feature completeness, production readiness.

Files or behavior to change:

- `site/marketing/src/pages/404.astro`
- `site/marketing/scripts/check.mjs`

Implementation scope:

- include links to `/en/`, `/fi/`, GitHub, and docs
- avoid collecting user input

Validation or proof:

- `make marketing-site-check`
- `make marketing-site-production-check`

Expected score impact: `+0.1` to `+0.3`.

Fix type: implementation, UX.

Implementation rules:

- implement the ticket in the smallest sensible step
- create a Conventional Commit after validation passes

## Epic E3 - Browser Proof And Consent Assurance [ ]

Description: Move from source-string checks to browser-level proof for layout, language routing, and consent-gated analytics.

### Ticket E3-T1 - Add Playwright smoke tests for routing, mobile nav, and consent [ ]

Description: Add a browser test that builds/serves the site and verifies the critical user flows.

Affected readiness dimension: tests, security and open-source trust, production readiness.

Files or behavior to change:

- `site/marketing/package.json`
- `site/marketing/package-lock.json`
- `site/marketing/tests/`
- `Makefile`

Implementation scope:

- verify `/en/` and `/fi/`
- verify root default to English
- verify mobile menu opens without wrapping into many rows
- verify `Accept all` and `Reject optional` controls exist
- verify no Google script node exists before acceptance
- verify Google script node appears only when a measurement ID is configured and `Accept all` is clicked

Validation or proof:

- `npm --prefix site/marketing run test:browser`
- `make marketing-site-check`
- `make marketing-site-production-check`

Expected score impact: `+0.5` to `+0.8`.

Fix type: tests, frontend security.

Implementation rules:

- use `frontend-security-loop` because this touches consent and browser behavior
- keep tests deterministic and local
- do not call live Google Analytics
- create a Conventional Commit after validation passes

### Ticket E3-T2 - Add accessibility smoke checks [ ]

Description: Add automated accessibility checks for the main pages, navigation, consent dialog, and language switch.

Affected readiness dimension: production readiness, marketability, repository evidence quality.

Files or behavior to change:

- `site/marketing/tests/`
- `site/marketing/package.json`
- `Makefile`

Implementation scope:

- use an automated accessibility checker or Playwright accessibility assertions
- cover keyboard navigation through header/menu/consent controls
- record limitations of automated a11y checks

Validation or proof:

- local a11y test command
- `make marketing-site-check`

Expected score impact: `+0.3` to `+0.5`.

Fix type: tests, accessibility.

Implementation rules:

- keep checks local and deterministic
- create a Conventional Commit after validation passes

### Ticket E3-T3 - Add responsive screenshot artifacts for review [ ]

Description: Generate or document desktop and mobile screenshots for the homepage/contact/privacy pages to catch hero and navigation regressions.

Affected readiness dimension: repository evidence quality, marketability.

Files or behavior to change:

- `site/marketing/tests/` or `docs/assets/`
- `docs/how-to/publish-marketing-site.md`

Implementation scope:

- desktop and mobile viewport proof
- ensure generated artifacts do not bloat the repository unless intentionally checked in

Validation or proof:

- screenshot-generation command
- manual inspection notes or automated pixel nonblank checks

Expected score impact: `+0.2` to `+0.4`.

Fix type: tests, visual QA.

Implementation rules:

- do not commit large generated artifacts unless they are intentionally curated docs assets
- create a Conventional Commit after validation passes

## Epic E4 - Privacy And Static Hosting Hardening [ ]

Description: Document and enforce the privacy/security limitations of a consent-gated GitHub Pages marketing site.

### Ticket E4-T1 - Document GA property and privacy configuration assumptions [ ]

Description: Document which GA settings are operator responsibilities and which are enforced by source code.

Affected readiness dimension: security and open-source trust.

Files or behavior to change:

- `docs/how-to/publish-marketing-site.md`
- `site/marketing/src/data/site.ts` privacy page copy if needed

Implementation scope:

- state that `G-XC2ESEHQ3W` is public client-side configuration, not a secret
- state that GA account access, retention, data sharing, and property settings are external
- keep the current no-sensitive-data warning

Validation or proof:

- `make docs-check`
- `make marketing-site-production-check`

Expected score impact: `+0.2` to `+0.3`.

Fix type: documentation, privacy.

Implementation rules:

- use `secrets-logging-privacy-loop` because this touches analytics/privacy expectations
- create a Conventional Commit after validation passes

### Ticket E4-T2 - Document GitHub Pages security-header limits [ ]

Description: Explain what security headers can and cannot be controlled on GitHub Pages and what that means for the static site.

Affected readiness dimension: security and open-source trust, operations.

Files or behavior to change:

- `docs/how-to/publish-marketing-site.md`
- possibly `docs/reference/external-controls-matrix.md`

Implementation scope:

- state that GitHub Pages does not provide arbitrary per-site header configuration
- avoid claiming CSP/HSTS settings are project-enforced unless verified
- distinguish `.app` browser HTTPS requirements from repository-controlled security headers

Validation or proof:

- `make docs-check`

Expected score impact: `+0.2` to `+0.3`.

Fix type: documentation, claim reduction.

Implementation rules:

- keep wording conservative
- create a Conventional Commit after validation passes

### Ticket E4-T3 - Strengthen consent validation in the checker [ ]

Description: Make the site checker inspect generated HTML for no direct Google tag script before consent, not only source-string markers.

Affected readiness dimension: security and open-source trust, tests.

Files or behavior to change:

- `site/marketing/scripts/check.mjs`

Implementation scope:

- assert generated `dist/en/index.html` and `dist/fi/index.html` do not include a static `<script src="https://www.googletagmanager.com/...">`
- assert the measurement ID appears only in consent-controlled data attributes or inline code paths
- keep the existing consent source checks

Validation or proof:

- `make marketing-site-check`
- `make marketing-site-production-check`

Expected score impact: `+0.2` to `+0.4`.

Fix type: tests, frontend security.

Implementation rules:

- use `frontend-security-loop`
- create a Conventional Commit after validation passes

## Epic E5 - Marketing Proof And Differentiation [ ]

Description: Add proof artifacts that make the site more convincing without adding unsupported compliance or security claims.

### Ticket E5-T1 - Add a visible sample evidence package path [ ]

Description: Link from the homepage to the existing local package viewer or sample customer package documentation.

Affected readiness dimension: marketability, differentiation, feature completeness.

Files or behavior to change:

- `site/marketing/src/data/site.ts`
- maybe `site/marketing/src/templates/MarketingPage.astro`
- related docs links

Implementation scope:

- surface a "View sample evidence package" or similar path
- keep wording clear that the sample is illustrative and not compliance proof

Validation or proof:

- `make marketing-site-check`
- `make docs-check`

Expected score impact: `+0.4` to `+0.7`.

Fix type: implementation, marketability.

Implementation rules:

- avoid broad product claims
- create a Conventional Commit after validation passes

### Ticket E5-T2 - Add a concise comparison section [ ]

Description: Add a site section that contrasts Evydence with scanner exports, broad GRC tools, trust centers, and DIY scripts using conservative wording.

Affected readiness dimension: differentiation, marketability.

Files or behavior to change:

- `site/marketing/src/data/site.ts`

Implementation scope:

- adapt from existing repository commercial comparison docs
- avoid naming competitors unless claims are sourced and current
- state that Evydence supports evidence organization rather than replacing review

Validation or proof:

- `make marketing-site-check`
- `make docs-check`

Expected score impact: `+0.3` to `+0.5`.

Fix type: content, positioning.

Implementation rules:

- keep wording narrow and defensible
- create a Conventional Commit after validation passes

## Epic E6 - External Trust Settings [e]

Description: Track provider/account settings that affect public readiness but cannot be completed by editing the repository.

### Ticket E6-T1 - Verify GitHub Pages Enforce HTTPS [e]

Description: Confirm GitHub Pages is serving `https://evydence.app` with HTTPS enforced after DNS and certificate provisioning.

Affected readiness dimension: production readiness, security trust.

Files or behavior to change:

- GitHub repository Pages settings

Implementation scope:

- external GitHub settings; cannot be completed inside source code

Validation or proof:

- `curl -I http://evydence.app` should redirect or fail closed appropriately
- `curl -I https://evydence.app` should return a successful HTTPS response

Expected score impact: `+0.3` to `+0.5`.

Fix type: external provider setting.

Implementation rules:

- record proof in a future audit or deployment note

### Ticket E6-T2 - Verify GA property privacy/account settings [e]

Description: Confirm the Google Analytics property uses intended retention, access, data-sharing, and privacy settings.

Affected readiness dimension: security and open-source trust.

Files or behavior to change:

- Google Analytics account/property configuration

Implementation scope:

- external Google account work; cannot be completed inside source code

Validation or proof:

- private operator checklist or screenshot, without exposing account secrets
- confirm no sensitive data collection events are configured

Expected score impact: `+0.2` to `+0.4`.

Fix type: external provider setting, privacy.

Implementation rules:

- do not publish account secrets or private analytics data

### Ticket E6-T3 - Verify branch protection and Pages deployment permissions [e]

Description: Confirm public branch protection and GitHub Pages deployment permissions match the project risk profile.

Affected readiness dimension: security and open-source trust, release integrity.

Files or behavior to change:

- GitHub branch protection settings
- GitHub Pages environment protection settings, if used

Implementation scope:

- external GitHub settings; cannot be completed inside source code

Validation or proof:

- branch protection settings review
- required checks include relevant CI/site checks after workflow is public

Expected score impact: `+0.2` to `+0.4`.

Fix type: external provider setting, release process.

Implementation rules:

- do not weaken repository settings to make deployment easier
