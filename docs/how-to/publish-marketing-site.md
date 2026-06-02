# Publish The Marketing Site

Use this guide to publish the static Astro marketing site to GitHub Pages at
`https://evydence.app`.

The website is product positioning and project navigation. It is not release
evidence, legal compliance proof, certification, vulnerability coverage, or a
security guarantee.

## Source

The marketing site lives in `site/marketing`.

Local development defaults to the project Pages path:

```bash
npm --prefix site/marketing run dev -- --host 127.0.0.1 --port 4321
```

Open `http://127.0.0.1:4321/evydence/en/`.

## Production Build

The production GitHub Pages workflow builds with these public client-side
values:

```text
PUBLIC_SITE_URL=https://evydence.app
PUBLIC_SITE_BASE=/
PUBLIC_GA_MEASUREMENT_ID=G-XC2ESEHQ3W
```

`PUBLIC_GA_MEASUREMENT_ID` is not a server secret. It appears in browser-side
JavaScript only after the visitor chooses `Accept all` in the consent banner.
The site must keep Google tags blocked until that choice is stored.

Run the same production build check locally with:

```bash
make marketing-site-production-check
```

## GitHub Pages

The Pages workflow is `.github/workflows/marketing-site-pages.yml`.

Before relying on the domain, configure repository Pages settings:

1. Set the Pages source to GitHub Actions.
2. Set the custom domain to `evydence.app`.
3. Wait for GitHub to provision HTTPS.
4. Enable `Enforce HTTPS`.

The checked `site/marketing/public/CNAME` file is copied into the static site
artifact and contains:

```text
evydence.app
```

## DNS

Configure the apex records at the domain provider:

```text
evydence.app  A     185.199.108.153
evydence.app  A     185.199.109.153
evydence.app  A     185.199.110.153
evydence.app  A     185.199.111.153
```

Optional IPv6 records:

```text
evydence.app  AAAA  2606:50c0:8000::153
evydence.app  AAAA  2606:50c0:8001::153
evydence.app  AAAA  2606:50c0:8002::153
evydence.app  AAAA  2606:50c0:8003::153
```

For `www`:

```text
www.evydence.app  CNAME  aatuh.github.io
```

Verify DNS with:

```bash
dig +short evydence.app A
dig +short evydence.app AAAA
dig +short www.evydence.app CNAME
```

## Validation

Run:

```bash
npm --prefix site/marketing audit --audit-level=moderate
make marketing-site-production-check
make docs-check
```

Do not publish a site change that loads Google Analytics before consent,
removes the `/en/` and `/fi/` routes, or introduces claims that Evydence
provides legal compliance, certification, complete SBOMs, authoritative scanner
results, or secure releases.
