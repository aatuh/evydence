export type Locale = "en" | "fi";

export type PageKey =
  | "home"
  | "product"
  | "customerReview"
  | "releasePackage"
  | "commercial"
  | "status"
  | "glossary"
  | "cra"
  | "contact"
  | "privacyCookies";

type Section = {
  eyebrow?: string;
  title: string;
  body?: string[];
  bullets?: string[];
  cards?: Array<{ title: string; body: string }>;
  table?: Array<{ left: string; right: string }>;
};

export type PageContent = {
  key: PageKey;
  title: string;
  navTitle: string;
  metaTitle: string;
  description: string;
  eyebrow?: string;
  heroTitle: string;
  heroBody: string[];
  primaryCta: string;
  secondaryCta: string;
  sections: Section[];
};

export const localeNames: Record<Locale, string> = {
  en: "English",
  fi: "Suomi"
};

export const routes: Record<PageKey, Record<Locale, string>> = {
  home: { en: "/en/", fi: "/fi/" },
  product: { en: "/en/product/", fi: "/fi/tuote/" },
  customerReview: {
    en: "/en/use-cases/customer-security-review/",
    fi: "/fi/kayttotapaukset/asiakkaan-tietoturvakatselmus/"
  },
  releasePackage: {
    en: "/en/use-cases/release-evidence-package/",
    fi: "/fi/kayttotapaukset/julkaisun-evidence-paketti/"
  },
  commercial: { en: "/en/commercial/", fi: "/fi/kaupallinen/" },
  status: { en: "/en/status/", fi: "/fi/tila/" },
  glossary: { en: "/en/resources/glossary/", fi: "/fi/resurssit/sanasto/" },
  cra: {
    en: "/en/resources/cra-readiness-evidence/",
    fi: "/fi/resurssit/cra-valmiuden-evidence/"
  },
  contact: { en: "/en/contact/", fi: "/fi/yhteys/" },
  privacyCookies: {
    en: "/en/privacy-cookies/",
    fi: "/fi/yksityisyys-evasteet/"
  }
};

export const orderedPageKeys: PageKey[] = [
  "home",
  "product",
  "customerReview",
  "releasePackage",
  "commercial",
  "status",
  "glossary",
  "cra",
  "contact",
  "privacyCookies"
];

export const navItems: PageKey[] = [
  "product",
  "customerReview",
  "commercial",
  "status",
  "glossary",
  "contact"
];

export const externalLinks = {
  github: "https://github.com/aatuh/evydence",
  docs: "https://github.com/aatuh/evydence/tree/master/docs",
  commercialEmail: "mailto:aatu@example.com?subject=Evydence%20Commercial%20Self-Hosted%20inquiry"
};

const en: Record<PageKey, PageContent> = {
  home: {
    key: "home",
    title: "Home",
    navTitle: "Home",
    metaTitle: "Evydence - release security evidence without the scramble",
    description:
      "Evydence helps software vendors answer customer release-security questions with organized, verifiable evidence.",
    eyebrow: "Self-hosted release evidence",
    heroTitle: "Stop scrambling when customers ask for release security evidence.",
    heroBody: [
      "Evydence helps software vendors organize the proof behind a software release: what was shipped, what was inside it, which vulnerabilities were reviewed, what decisions were made, and what can safely be shared with customers.",
      "Run it self-hosted, keep technical truth on GitHub, and use commercial terms when your organization needs them."
    ],
    primaryCta: "Ask about Commercial Self-Hosted",
    secondaryCta: "View GitHub",
    sections: [
      {
        eyebrow: "The problem",
        title: "Customer security reviews are becoming more detailed.",
        body: [
          "A customer may ask what third-party components are inside a release, whether known vulnerabilities are present, whether a CVE affects your product, who reviewed the decision, and what proof can be verified.",
          "For many teams, the answer is scattered across scanner exports, CI logs, tickets, chat, spreadsheets, object storage, and one-off PDFs."
        ]
      },
      {
        eyebrow: "The outcome",
        title: "Evydence gives each release an evidence trail.",
        bullets: [
          "software component inventory",
          "vulnerability scan results",
          "vulnerability decisions",
          "approvals and exceptions",
          "build and artifact proof",
          "release-readiness reports",
          "signed bundles",
          "customer-safe packages"
        ]
      },
      {
        title: "Before and after Evydence",
        table: [
          { left: "Evidence scattered across tools", right: "Evidence linked to a release" },
          { left: "Manual customer answers", right: "Repeatable customer package" },
          { left: "Decisions hidden in tickets or chat", right: "Decision trail with actor context" },
          { left: "Hard to explain not affected", right: "Reviewable vulnerability decision" },
          { left: "One-off PDF work", right: "Package generated from structured records" }
        ]
      },
      {
        title: "What it is not",
        body: [
          "Evydence is not a scanner, firewall, legal compliance engine, certification service, or guarantee that a release is secure.",
          "It helps organize technical evidence and release-security decisions so teams can answer review questions more clearly and repeatably."
        ]
      }
    ]
  },
  product: {
    key: "product",
    title: "Product",
    navTitle: "Product",
    metaTitle: "Product - Evydence",
    description: "A self-hosted evidence system for software releases.",
    eyebrow: "Product overview",
    heroTitle: "A self-hosted evidence system for software releases.",
    heroBody: [
      "Evydence keeps release evidence connected to the product, version, artifact, vulnerability, decision, approval, and customer package it belongs to."
    ],
    primaryCta: "Ask about Commercial Self-Hosted",
    secondaryCta: "View GitHub",
    sections: [
      {
        title: "Capture release evidence",
        body: [
          "Collect proof material around a release: component inventories, vulnerability scans, build metadata, artifact digests, source records, deployment events, and supporting files."
        ]
      },
      {
        title: "Record vulnerability decisions",
        body: [
          "When a known vulnerability appears, record whether it affects the release, why, who reviewed it, and what evidence supports the decision."
        ]
      },
      {
        title: "Generate customer-safe packages",
        body: [
          "Create packages that include evidence a customer can review without exposing unnecessary internal detail."
        ]
      },
      {
        title: "Verify the package",
        body: [
          "Use manifests, hashes, signatures, and audit-chain records to make the package reviewable instead of just another static document."
        ]
      },
      {
        title: "Self-hosted by design",
        body: [
          "Evydence is designed for teams that want to run the evidence system in their own environment, close to release, security, and CI/CD systems."
        ]
      }
    ]
  },
  customerReview: {
    key: "customerReview",
    title: "Customer security reviews",
    navTitle: "Use cases",
    metaTitle: "Customer security reviews - Evydence",
    description: "Turn customer security review questions into a repeatable release evidence workflow.",
    eyebrow: "Use case",
    heroTitle: "Customer security reviews should not require a scavenger hunt.",
    heroBody: [
      "Enterprise customers increasingly ask software vendors to explain what is inside a release, which known vulnerabilities are present, which ones actually affect the product, and what proof supports the answer.",
      "Evydence helps turn that review from a manual scramble into a repeatable release evidence workflow."
    ],
    primaryCta: "Ask about a release evidence pilot",
    secondaryCta: "View GitHub",
    sections: [
      {
        title: "The question that triggers the scramble",
        body: [
          "A customer asks: This CVE appears in your software bill of materials. Are we affected?",
          "Without a system, the answer may require checking the SBOM, vulnerability scanner, CI logs, build artifacts, internal tickets, approvals, release notes, and previous customer responses."
        ]
      },
      {
        title: "A clearer answer",
        bullets: [
          "yes, affected and fixed",
          "yes, affected and accepted with an exception",
          "no, present but not exploitable in this product context",
          "unknown, with documented gaps and next steps"
        ]
      },
      {
        title: "Before and after",
        table: [
          {
            left: "We think this is not exploitable. Let us check with engineering.",
            right: "For this release, the finding was reviewed, marked not affected, linked to supporting evidence, and included in the customer-safe package."
          }
        ]
      }
    ]
  },
  releasePackage: {
    key: "releasePackage",
    title: "Release evidence packages",
    navTitle: "Packages",
    metaTitle: "Release evidence packages - Evydence",
    description: "One release, one organized evidence package.",
    eyebrow: "Use case",
    heroTitle: "One release. One organized evidence package.",
    heroBody: [
      "An evidence package is a structured set of proof material for a software release.",
      "It can include what was shipped, what components were inside, which known vulnerabilities were found, how those findings were handled, who approved the decision, and what a customer can verify."
    ],
    primaryCta: "Ask about Commercial Self-Hosted",
    secondaryCta: "View GitHub",
    sections: [
      {
        title: "Suggested package contents",
        bullets: [
          "product and release identity",
          "shipped artifact references",
          "artifact hashes or digests",
          "SBOM/component inventory",
          "vulnerability scan summary",
          "vulnerability decisions",
          "exception or waiver records",
          "build/source provenance",
          "approval trail",
          "package manifest",
          "limitations and assumptions",
          "customer-safe redactions"
        ]
      },
      {
        title: "Important boundary",
        body: [
          "The package does not mean the release is perfectly secure.",
          "It means the team can show what was checked, what was decided, what is still unknown, and what evidence supports the answer."
        ]
      }
    ]
  },
  commercial: {
    key: "commercial",
    title: "Commercial",
    navTitle: "Commercial",
    metaTitle: "Commercial Self-Hosted Licensing - Evydence",
    description: "Commercial self-hosted licensing, async support, deployment review, and integration support.",
    eyebrow: "Commercial Self-Hosted",
    heroTitle: "Commercial Self-Hosted Licensing.",
    heroBody: [
      "Use Evydence under AGPL when that fits your organization.",
      "Buy Evydence Commercial Self-Hosted when you need private commercial terms, AGPL exception, async support, signed release/evidence delivery, or deployment review."
    ],
    primaryCta: "Start async commercial inquiry",
    secondaryCta: "View GitHub",
    sections: [
      {
        title: "Community AGPL vs Commercial Self-Hosted",
        table: [
          { left: "Public AGPL license", right: "Separate written commercial agreement" },
          { left: "Public GitHub issues", right: "Private async support" },
          { left: "Best-effort community help", right: "Agreed support and upgrade path" },
          { left: "Self-evaluation", right: "Optional deployment-readiness review" },
          { left: "AGPL obligations apply", right: "Extra permission for agreed use cases" }
        ]
      },
      {
        title: "Paid options",
        cards: [
          { title: "Commercial Self-Hosted License", body: "Private commercial terms, procurement-friendly licensing, and an agreed support path." },
          { title: "Async Support", body: "Private written support for troubleshooting, upgrade planning, deployment questions, and release evidence workflows." },
          { title: "Deployment Readiness Review", body: "Written review of configuration, backup/restore, evidence handling, deployment architecture, and known limitations." },
          { title: "Release Evidence Package Review", body: "Written review of one evidence package, including gaps, assumptions, limitations, and customer-safe sharing concerns." },
          { title: "Custom Integration", body: "Collector adapters, evidence workflows, report templates, CI/CD integration, or deployment hardening." }
        ]
      },
      {
        title: "Commercial boundary",
        body: [
          "Commercial terms do not turn Evydence into a legal compliance guarantee, security certification, vulnerability scanner, or managed SaaS service."
        ]
      }
    ]
  },
  status: {
    key: "status",
    title: "Status",
    navTitle: "Status",
    metaTitle: "Current status and limitations - Evydence",
    description: "Current status and supported self-hosted deployment profile.",
    eyebrow: "Status and limitations",
    heroTitle: "Current status and supported deployment profile.",
    heroBody: [
      "Evydence is intended for evaluation, pilots, and controlled internal self-hosted production after operator review.",
      "It is not marketed as a hosted SaaS product or a broad regulated-production platform."
    ],
    primaryCta: "Ask about deployment fit",
    secondaryCta: "View GitHub",
    sections: [
      {
        title: "Deployment fit",
        table: [
          { left: "Local technical evaluation", right: "Good fit" },
          { left: "Pilot with one product/release", right: "Good fit" },
          { left: "Controlled internal self-hosted use", right: "Candidate after review" },
          { left: "Regulated production", right: "Requires extra review" },
          { left: "Air-gapped production", right: "Requires transfer controls" },
          { left: "Hosted SaaS by Evydence", right: "Not currently offered" }
        ]
      },
      {
        title: "Why this page exists",
        body: [
          "This page filters out bad-fit use cases and increases trust with good-fit evaluators by stating limitations plainly."
        ]
      }
    ]
  },
  glossary: {
    key: "glossary",
    title: "Glossary",
    navTitle: "Glossary",
    metaTitle: "Plain-English glossary - Evydence",
    description: "Plain-English terms for release evidence, SBOMs, CVEs, VEX, and customer-safe packages.",
    eyebrow: "Resources",
    heroTitle: "Plain-English glossary.",
    heroBody: [
      "Short explanations for people evaluating release evidence workflows without needing every implementation detail."
    ],
    primaryCta: "Ask about Commercial Self-Hosted",
    secondaryCta: "View GitHub",
    sections: [
      {
        title: "Terms",
        cards: [
          { title: "Evidence", body: "Proof material around a software release: scan results, component lists, build records, vulnerability decisions, approvals, artifact hashes, release reports, and customer-safe files." },
          { title: "Evidence package", body: "An organized bundle of release proof that can be reviewed internally or shared with a customer." },
          { title: "SBOM", body: "A software ingredients list. It describes the components used inside software." },
          { title: "CVE", body: "A public identifier for a known software flaw." },
          { title: "VEX", body: "A structured way to explain whether a known vulnerability actually affects a specific product or release." },
          { title: "Customer-safe package", body: "A package that contains useful review evidence without exposing unnecessary internal details." },
          { title: "Release readiness", body: "A structured view of whether the release has expected evidence, decisions, approvals, and known limitations before it is shared or shipped." }
        ]
      }
    ]
  },
  cra: {
    key: "cra",
    title: "CRA-readiness evidence",
    navTitle: "CRA readiness",
    metaTitle: "Technical evidence organization for CRA readiness - Evydence",
    description: "Technical evidence organization for CRA-readiness work without legal compliance claims.",
    eyebrow: "Resources",
    heroTitle: "Technical evidence organization for CRA readiness.",
    heroBody: [
      "The EU Cyber Resilience Act is increasing attention on vulnerability handling, technical documentation, and product-security processes.",
      "Evydence does not provide legal compliance or certification, but it can help organize technical release evidence that product-security and compliance-readiness teams may need to review."
    ],
    primaryCta: "Ask about a release evidence review",
    secondaryCta: "View GitHub",
    sections: [
      {
        title: "Careful wording",
        body: [
          "Evydence can support CRA-readiness work by helping teams preserve release-level technical evidence, vulnerability decisions, SBOM records, package manifests, and known limitations."
        ]
      },
      {
        title: "Wording to avoid",
        bullets: [
          "Evydence makes you CRA compliant.",
          "Evydence certifies your releases.",
          "Evydence guarantees regulatory acceptance.",
          "Evydence proves your software is secure."
        ]
      }
    ]
  },
  contact: {
    key: "contact",
    title: "Contact",
    navTitle: "Contact",
    metaTitle: "Async commercial inquiry - Evydence",
    description: "Start an async commercial self-hosted inquiry.",
    eyebrow: "Async-first contact",
    heroTitle: "Async commercial inquiry.",
    heroBody: [
      "Evydence commercial support is async-first. Send context, deployment assumptions, release workflow notes, or commercial licensing questions. You will receive a written response."
    ],
    primaryCta: "Send async inquiry",
    secondaryCta: "View GitHub",
    sections: [
      {
        title: "What to include",
        bullets: [
          "your intended use",
          "target deployment model",
          "AGPL or commercial concerns",
          "support expectations",
          "target release workflow",
          "preferred next step"
        ]
      },
      {
        title: "Do not send sensitive evidence",
        body: [
          "Do not send raw evidence payloads, bearer tokens, private keys, database URLs, customer data, or unreleased package contents through the public contact path.",
          "A short scoping call can be requested after async context is shared."
        ]
      }
    ]
  },
  privacyCookies: {
    key: "privacyCookies",
    title: "Privacy and cookies",
    navTitle: "Privacy",
    metaTitle: "Privacy and cookies - Evydence",
    description: "How the marketing site handles necessary preferences and optional measurement.",
    eyebrow: "Privacy",
    heroTitle: "Privacy and cookies.",
    heroBody: [
      "The marketing site uses only necessary local preferences until you choose to accept optional site measurement.",
      "Optional measurement, when enabled, is limited to aggregate marketing-site events."
    ],
    primaryCta: "Manage cookie choices",
    secondaryCta: "View GitHub",
    sections: [
      {
        title: "What may be measured after acceptance",
        bullets: [
          "page views",
          "outbound GitHub clicks",
          "docs clicks",
          "contact clicks",
          "language switches"
        ]
      },
      {
        title: "What is not measured",
        body: [
          "The site must not track raw form text, email addresses, customer names, company names, evidence package data, tokens, query parameters containing secrets, or support content."
        ]
      },
      {
        title: "Changing your choice",
        body: [
          "Use the footer cookie preferences link to reopen the consent panel and change your optional measurement choice."
        ]
      }
    ]
  }
};

const fi: Record<PageKey, PageContent> = {
  home: {
    ...en.home,
    title: "Etusivu",
    navTitle: "Etusivu",
    metaTitle: "Evydence - julkaisun tietoturvaevidence ilman säätöä",
    description:
      "Evydence auttaa ohjelmistotoimittajia vastaamaan asiakkaiden julkaisun tietoturvakysymyksiin järjestetyllä ja todennettavalla evidencellä.",
    eyebrow: "Itse ylläpidettävä julkaisuevidence",
    heroTitle: "Lopeta kiireinen selvittely, kun asiakas pyytää julkaisun tietoturvaevidenceä.",
    heroBody: [
      "Evydence auttaa ohjelmistotoimittajia järjestämään ohjelmistojulkaisun taustalla olevan evidencen: mitä toimitettiin, mitä se sisälsi, mitkä haavoittuvuudet arvioitiin, mitä päätöksiä tehtiin ja mitä voidaan jakaa asiakkaalle turvallisesti.",
      "Aja järjestelmää itse, pidä tekninen totuus GitHubissa ja käytä kaupallisia ehtoja, kun organisaatiosi tarvitsee niitä."
    ],
    primaryCta: "Kysy Commercial Self-Hosted -ehdoista",
    secondaryCta: "Avaa GitHub",
    sections: [
      {
        eyebrow: "Ongelma",
        title: "Asiakkaiden tietoturvakatselmukset ovat yhä yksityiskohtaisempia.",
        body: [
          "Asiakas voi kysyä, mitä kolmannen osapuolen komponentteja julkaisu sisältää, onko tunnettuja haavoittuvuuksia mukana, vaikuttaako CVE tuotteeseen, kuka arvioi päätöksen ja mitä näyttöä voidaan todentaa.",
          "Monessa tiimissä vastaus on hajallaan skannerivienneissä, CI-lokeissa, tiketeissä, keskusteluissa, taulukoissa, objektitallennuksessa ja kertaluonteisissa PDF-tiedostoissa."
        ]
      },
      {
        eyebrow: "Lopputulos",
        title: "Evydence antaa jokaiselle julkaisulle evidence-polun.",
        bullets: [
          "ohjelmistokomponenttien inventaario",
          "haavoittuvuusskannausten tulokset",
          "haavoittuvuuspäätökset",
          "hyväksynnät ja poikkeukset",
          "koonti- ja artefaktievidence",
          "julkaisuvalmiuden raportit",
          "allekirjoitetut bundle-paketit",
          "asiakkaalle turvalliset paketit"
        ]
      },
      {
        title: "Ennen ja jälkeen Evydencen",
        table: [
          { left: "Evidence on hajallaan työkaluissa", right: "Evidence on linkitetty julkaisuun" },
          { left: "Asiakasvastaukset ovat käsityötä", right: "Asiakaspaketti voidaan toistaa" },
          { left: "Päätökset ovat piilossa tiketeissä tai chatissa", right: "Päätöspolku sisältää tekijäkontekstin" },
          { left: "Not affected -päätöstä on vaikea selittää", right: "Haavoittuvuuspäätös on katselmoitavissa" },
          { left: "PDF-työ tehdään kertaluonteisesti", right: "Paketti syntyy rakenteisista tietueista" }
        ]
      },
      {
        title: "Mitä Evydence ei ole",
        body: [
          "Evydence ei ole skanneri, palomuuri, juridinen vaatimustenmukaisuuskone, sertifiointipalvelu tai takuu siitä, että julkaisu on turvallinen.",
          "Se auttaa järjestämään teknisen evidencen ja julkaisun tietoturvapäätökset, jotta tiimit voivat vastata katselmuskysymyksiin selkeämmin ja toistettavammin."
        ]
      }
    ]
  },
  product: {
    ...en.product,
    title: "Tuote",
    navTitle: "Tuote",
    metaTitle: "Tuote - Evydence",
    description: "Itse ylläpidettävä evidence-järjestelmä ohjelmistojulkaisuille.",
    eyebrow: "Tuotekuvaus",
    heroTitle: "Itse ylläpidettävä evidence-järjestelmä ohjelmistojulkaisuille.",
    heroBody: [
      "Evydence pitää julkaisuevidencen kytkettynä tuotteeseen, versioon, artefaktiin, haavoittuvuuteen, päätökseen, hyväksyntään ja asiakaspakettiin."
    ],
    primaryCta: "Kysy Commercial Self-Hosted -ehdoista",
    secondaryCta: "Avaa GitHub",
    sections: [
      { title: "Kerää julkaisuevidence", body: ["Kerää julkaisun ympärillä oleva todistusaineisto: komponenttilistat, haavoittuvuusskannaukset, koontimetatiedot, artefaktien digestit, lähdekooditietueet, käyttöönotot ja tukevat tiedostot."] },
      { title: "Tallenna haavoittuvuuspäätökset", body: ["Kun tunnettu haavoittuvuus löytyy, tallenna vaikuttaako se julkaisuun, miksi, kuka sen arvioi ja mikä evidence tukee päätöstä."] },
      { title: "Luo asiakkaalle turvallisia paketteja", body: ["Luo paketteja, jotka sisältävät asiakkaalle hyödyllisen evidencen ilman tarpeetonta sisäistä yksityiskohtaa."] },
      { title: "Todenna paketti", body: ["Käytä manifestteja, tiivisteitä, allekirjoituksia ja audit chain -tietueita, jotta paketti on katselmoitava eikä vain uusi staattinen dokumentti."] },
      { title: "Itse ylläpidettävä lähtökohta", body: ["Evydence on tarkoitettu tiimeille, jotka haluavat ajaa evidence-järjestelmää omassa ympäristössään lähellä julkaisu-, tietoturva- ja CI/CD-järjestelmiä."] }
    ]
  },
  customerReview: {
    ...en.customerReview,
    title: "Asiakkaan tietoturvakatselmukset",
    navTitle: "Käyttötapaukset",
    metaTitle: "Asiakkaan tietoturvakatselmukset - Evydence",
    description: "Muuta asiakkaan tietoturvakysymykset toistettavaksi julkaisuevidence-työnkuluksi.",
    eyebrow: "Käyttötapaus",
    heroTitle: "Asiakkaan tietoturvakatselmuksen ei pitäisi olla aarteenetsintä.",
    heroBody: [
      "Yritysasiakkaat kysyvät yhä useammin, mitä julkaisu sisältää, mitä tunnettuja haavoittuvuuksia löytyy, mitkä niistä todella vaikuttavat tuotteeseen ja mikä evidence tukee vastausta.",
      "Evydence auttaa muuttamaan katselmuksen käsityöstä toistettavaksi julkaisuevidence-työnkuluksi."
    ],
    primaryCta: "Kysy julkaisuevidence-pilotista",
    secondaryCta: "Avaa GitHub",
    sections: [
      { title: "Kysymys, joka käynnistää selvityksen", body: ["Asiakas kysyy: Tämä CVE näkyy ohjelmiston SBOMissa. Vaikuttaako se meihin?", "Ilman järjestelmää vastaus voi vaatia SBOMin, skannerin, CI-lokien, artefaktien, sisäisten tikettien, hyväksyntöjen, julkaisutietojen ja aiempien asiakasvastausten läpikäyntiä."] },
      { title: "Selkeämpi vastaus", bullets: ["kyllä, vaikuttaa ja on korjattu", "kyllä, vaikuttaa ja on hyväksytty poikkeuksella", "ei, mukana mutta ei hyödynnettävissä tässä tuotekontekstissa", "tuntematon, dokumentoiduilla aukoilla ja seuraavilla toimilla"] },
      { title: "Ennen ja jälkeen", table: [{ left: "Uskomme, ettei tämä ole hyödynnettävissä. Tarkistamme asian kehitystiimiltä.", right: "Tälle julkaisulle löydös arvioitiin, merkittiin not affected -tilaan, linkitettiin tukevaan evidenceen ja sisällytettiin asiakaspakettiin." }] }
    ]
  },
  releasePackage: {
    ...en.releasePackage,
    title: "Julkaisun evidence-paketit",
    navTitle: "Paketit",
    metaTitle: "Julkaisun evidence-paketit - Evydence",
    description: "Yksi julkaisu, yksi järjestetty evidence-paketti.",
    eyebrow: "Käyttötapaus",
    heroTitle: "Yksi julkaisu. Yksi järjestetty evidence-paketti.",
    heroBody: [
      "Evidence-paketti on rakenteinen todistusaineisto ohjelmistojulkaisulle.",
      "Se voi sisältää mitä toimitettiin, mitä komponentteja oli mukana, mitä tunnettuja haavoittuvuuksia löytyi, miten ne käsiteltiin, kuka hyväksyi päätöksen ja mitä asiakas voi todentaa."
    ],
    primaryCta: "Kysy Commercial Self-Hosted -ehdoista",
    secondaryCta: "Avaa GitHub",
    sections: [
      { title: "Suositeltu sisältö", bullets: ["tuotteen ja julkaisun identiteetti", "toimitettujen artefaktien viitteet", "artefaktien tiivisteet tai digestit", "SBOM/komponentti-inventaario", "haavoittuvuusskannauksen yhteenveto", "haavoittuvuuspäätökset", "poikkeus- tai waiver-tietueet", "koonti- ja lähdekoodiprovenanssi", "hyväksyntäpolku", "pakettimanifesti", "rajoitukset ja oletukset", "asiakkaalle turvalliset redaktiot"] },
      { title: "Tärkeä raja", body: ["Paketti ei tarkoita, että julkaisu olisi täydellisen turvallinen.", "Se tarkoittaa, että tiimi voi näyttää, mitä tarkistettiin, mitä päätettiin, mitä on yhä tuntematonta ja mikä evidence tukee vastausta."] }
    ]
  },
  commercial: {
    ...en.commercial,
    title: "Kaupallinen",
    navTitle: "Kaupallinen",
    metaTitle: "Commercial Self-Hosted -lisensointi - Evydence",
    description: "Kaupallinen itse ylläpidettävä lisensointi, async-tuki, käyttöönottokatselmus ja integraatiotuki.",
    eyebrow: "Commercial Self-Hosted",
    heroTitle: "Commercial Self-Hosted -lisensointi.",
    heroBody: [
      "Käytä Evydenceä AGPL-lisenssillä, kun se sopii organisaatiollesi.",
      "Osta Commercial Self-Hosted, kun tarvitset yksityiset kaupalliset ehdot, AGPL-poikkeuksen, async-tuen, allekirjoitetun julkaisu/evidence-toimituksen tai käyttöönottokatselmuksen."
    ],
    primaryCta: "Aloita async-kaupallinen kysely",
    secondaryCta: "Avaa GitHub",
    sections: [
      { title: "Community AGPL vs Commercial Self-Hosted", table: [{ left: "Julkinen AGPL-lisenssi", right: "Erillinen kirjallinen kaupallinen sopimus" }, { left: "Julkiset GitHub-issuet", right: "Yksityinen async-tuki" }, { left: "Best-effort-yhteisöapu", right: "Sovittu tuki- ja päivityspolku" }, { left: "Oma arviointi", right: "Valinnainen deployment readiness -katselmus" }, { left: "AGPL-velvoitteet pätevät", right: "Lisälupa sovittuihin käyttötapauksiin" }] },
      { title: "Maksulliset vaihtoehdot", cards: [{ title: "Commercial Self-Hosted License", body: "Yksityiset kaupalliset ehdot, hankintaystävällinen lisensointi ja sovittu tukipolku." }, { title: "Async Support", body: "Yksityinen kirjallinen tuki vianrajoitukseen, päivityssuunnitteluun, käyttöönottokysymyksiin ja julkaisuevidence-työnkulkuihin." }, { title: "Deployment Readiness Review", body: "Kirjallinen katselmus konfiguraatiosta, varmistuksista, evidencen käsittelystä, arkkitehtuurista ja tunnetuista rajoituksista." }, { title: "Release Evidence Package Review", body: "Kirjallinen katselmus yhdestä evidence-paketista, mukaan lukien aukot, oletukset, rajoitukset ja asiakkaalle turvallinen jakaminen." }, { title: "Custom Integration", body: "Collector-adapterit, evidence-työnkulut, raporttipohjat, CI/CD-integraatio tai deployment-kovennus." }] },
      { title: "Kaupallinen raja", body: ["Kaupalliset ehdot eivät tee Evydencestä juridista vaatimustenmukaisuustakuuta, tietoturvasertifiointia, haavoittuvuusskanneria tai hallittua SaaS-palvelua."] }
    ]
  },
  status: {
    ...en.status,
    title: "Tila",
    navTitle: "Tila",
    metaTitle: "Nykyinen tila ja rajoitukset - Evydence",
    description: "Nykyinen tila ja tuettu itse ylläpidettävä käyttöprofiili.",
    eyebrow: "Tila ja rajoitukset",
    heroTitle: "Nykyinen tila ja tuettu käyttöprofiili.",
    heroBody: [
      "Evydence on tarkoitettu arviointiin, pilotteihin ja hallittuun sisäiseen itse ylläpidettävään tuotantokäyttöön operaattorin katselmuksen jälkeen.",
      "Sitä ei markkinoida hostattuna SaaS-tuotteena tai laajana reguloidun tuotannon alustana."
    ],
    primaryCta: "Kysy käyttöönottosopivuudesta",
    secondaryCta: "Avaa GitHub",
    sections: [
      { title: "Käyttöprofiilin sopivuus", table: [{ left: "Paikallinen tekninen arviointi", right: "Hyvä sopivuus" }, { left: "Pilotti yhdellä tuotteella/julkaisulla", right: "Hyvä sopivuus" }, { left: "Hallittu sisäinen itse ylläpidettävä käyttö", right: "Kandidaatti katselmuksen jälkeen" }, { left: "Reguloitu tuotanto", right: "Vaatii lisäkatselmuksen" }, { left: "Air-gapped-tuotanto", right: "Vaatii siirtokontrollit" }, { left: "Evydencen hostattu SaaS", right: "Ei tällä hetkellä tarjolla" }] },
      { title: "Miksi tämä sivu on olemassa", body: ["Tämä sivu suodattaa huonosti sopivat käyttötapaukset ja lisää luottamusta sopivien arvioijien kanssa kertomalla rajoitukset suoraan."] }
    ]
  },
  glossary: {
    ...en.glossary,
    title: "Sanasto",
    navTitle: "Sanasto",
    metaTitle: "Selkokielinen sanasto - Evydence",
    description: "Selkokieliset termit julkaisuevidencestä, SBOMeista, CVE-tunnuksista, VEXistä ja asiakaspaketeista.",
    eyebrow: "Resurssit",
    heroTitle: "Selkokielinen sanasto.",
    heroBody: ["Lyhyet selitykset ihmisille, jotka arvioivat julkaisuevidence-työnkulkuja ilman kaikkia toteutusyksityiskohtia."],
    primaryCta: "Kysy Commercial Self-Hosted -ehdoista",
    secondaryCta: "Avaa GitHub",
    sections: [
      { title: "Termit", cards: [{ title: "Evidence", body: "Julkaisun ympärillä oleva todistusaineisto: skannaustulokset, komponenttilistat, koontitietueet, haavoittuvuuspäätökset, hyväksynnät, artefaktitiivisteet, julkaisuraportit ja asiakkaalle turvalliset tiedostot." }, { title: "Evidence-paketti", body: "Järjestetty julkaisun todistusaineistopaketti, jota voidaan katselmoida sisäisesti tai jakaa asiakkaalle." }, { title: "SBOM", body: "Ohjelmiston ainesosalista. Se kuvaa ohjelmistossa käytetyt komponentit." }, { title: "CVE", body: "Julkinen tunniste tunnetulle ohjelmistovirheelle." }, { title: "VEX", body: "Rakenteinen tapa selittää, vaikuttaako tunnettu haavoittuvuus tiettyyn tuotteeseen tai julkaisuun." }, { title: "Asiakkaalle turvallinen paketti", body: "Paketti, joka sisältää hyödyllisen katselmusevidencen paljastamatta tarpeettomia sisäisiä yksityiskohtia." }, { title: "Julkaisuvalmius", body: "Rakenteinen näkymä siihen, onko julkaisulla odotettu evidence, päätökset, hyväksynnät ja tunnetut rajoitukset ennen jakamista tai toimitusta." }] }
    ]
  },
  cra: {
    ...en.cra,
    title: "CRA-valmiuden evidence",
    navTitle: "CRA-valmius",
    metaTitle: "Teknisen evidencen järjestäminen CRA-valmiutta varten - Evydence",
    description: "Teknisen evidencen järjestäminen CRA-valmiustyöhön ilman juridisia vaatimustenmukaisuusväitteitä.",
    eyebrow: "Resurssit",
    heroTitle: "Teknisen evidencen järjestäminen CRA-valmiutta varten.",
    heroBody: [
      "EU:n Cyber Resilience Act lisää huomiota haavoittuvuuksien käsittelyyn, tekniseen dokumentaatioon ja tuoteturvallisuusprosesseihin.",
      "Evydence ei tarjoa juridista vaatimustenmukaisuutta tai sertifiointia, mutta se voi auttaa järjestämään teknistä julkaisuevidenceä, jota tuoteturvallisuus- ja compliance readiness -tiimit voivat tarvita katselmuksissa."
    ],
    primaryCta: "Kysy release evidence -katselmuksesta",
    secondaryCta: "Avaa GitHub",
    sections: [
      { title: "Varovainen sanamuoto", body: ["Evydence voi tukea CRA-valmiustyötä auttamalla tiimejä säilyttämään julkaisutason teknistä evidenceä, haavoittuvuuspäätöksiä, SBOM-tietueita, pakettimanifesteja ja tunnettuja rajoituksia."] },
      { title: "Vältettävät sanamuodot", bullets: ["Evydence tekee sinusta CRA-yhteensopivan.", "Evydence sertifioi julkaisusi.", "Evydence takaa viranomaisen hyväksynnän.", "Evydence todistaa, että ohjelmistosi on turvallinen."] }
    ]
  },
  contact: {
    ...en.contact,
    title: "Yhteys",
    navTitle: "Yhteys",
    metaTitle: "Async-kaupallinen kysely - Evydence",
    description: "Aloita async-kysely Commercial Self-Hosted -käytöstä.",
    eyebrow: "Async ensin",
    heroTitle: "Async-kaupallinen kysely.",
    heroBody: ["Evydencen kaupallinen tuki on async-first. Lähetä konteksti, käyttöoletukset, julkaisutyönkulun muistiinpanot tai lisensointikysymykset. Saat kirjallisen vastauksen."],
    primaryCta: "Lähetä async-kysely",
    secondaryCta: "Avaa GitHub",
    sections: [
      { title: "Mitä mukaan", bullets: ["suunniteltu käyttötapa", "tavoiteltu käyttöönottomalli", "AGPL- tai kaupalliset huolenaiheet", "tukiodotukset", "tavoiteltu julkaisutyönkulku", "toivottu seuraava askel"] },
      { title: "Älä lähetä arkaluonteista evidenceä", body: ["Älä lähetä raw evidence -payloadia, bearer-tokeneita, yksityisiä avaimia, tietokanta-URL-osoitteita, asiakasdataa tai julkaisemattomia pakettisisältöjä julkisen yhteyspolun kautta.", "Lyhyttä rajauspuhelua voi pyytää sen jälkeen, kun async-konteksti on jaettu."] }
    ]
  },
  privacyCookies: {
    ...en.privacyCookies,
    title: "Yksityisyys ja evästeet",
    navTitle: "Yksityisyys",
    metaTitle: "Yksityisyys ja evästeet - Evydence",
    description: "Miten markkinointisivusto käsittelee välttämättömiä asetuksia ja valinnaista mittausta.",
    eyebrow: "Yksityisyys",
    heroTitle: "Yksityisyys ja evästeet.",
    heroBody: [
      "Markkinointisivusto käyttää vain välttämättömiä paikallisia valintoja, kunnes päätät hyväksyä valinnaisen sivustomittauksen.",
      "Kun valinnainen mittaus on käytössä, se rajoittuu koottuihin markkinointisivuston tapahtumiin."
    ],
    primaryCta: "Hallitse evästevalintoja",
    secondaryCta: "Avaa GitHub",
    sections: [
      { title: "Mitä voidaan mitata hyväksynnän jälkeen", bullets: ["sivunäkymät", "ulospäin lähtevät GitHub-klikkaukset", "dokumentaatioklikkaukset", "yhteydenottoklikkaukset", "kielenvaihdot"] },
      { title: "Mitä ei mitata", body: ["Sivusto ei saa seurata lomakkeen raakatekstiä, sähköpostiosoitteita, asiakkaiden nimiä, yritysten nimiä, evidence-pakettien dataa, tokeneita, salaisuuksia sisältäviä kyselyparametreja tai tukisisältöä."] },
      { title: "Valinnan muuttaminen", body: ["Avaa suostumuspaneeli uudelleen alatunnisteen evästeasetusten linkistä ja muuta valinnaisen mittauksen valintaa."] }
    ]
  }
};

export const content: Record<Locale, Record<PageKey, PageContent>> = { en, fi };

export const ui = {
  en: {
    skip: "Skip to content",
    language: "Language",
    docs: "Docs",
    github: "GitHub",
    footerTagline: "Self-hosted release evidence for software vendors.",
    footerBoundary:
      "Evydence is not a legal compliance service, certification authority, vulnerability scanner, hosted SaaS, or guarantee of release security.",
    cookiePreferences: "Cookie preferences",
    outboundGitHub: "View GitHub",
    contactHref: externalLinks.commercialEmail
  },
  fi: {
    skip: "Siirry sisältöön",
    language: "Kieli",
    docs: "Dokumentaatio",
    github: "GitHub",
    footerTagline: "Itse ylläpidettävä julkaisuevidence ohjelmistotoimittajille.",
    footerBoundary:
      "Evydence ei ole juridinen vaatimustenmukaisuuspalvelu, sertifiointitaho, haavoittuvuusskanneri, hostattu SaaS-palvelu tai takuu julkaisun turvallisuudesta.",
    cookiePreferences: "Evästeasetukset",
    outboundGitHub: "Avaa GitHub",
    contactHref: externalLinks.commercialEmail
  }
} satisfies Record<Locale, Record<string, string>>;

export function routeFor(pageKey: PageKey, locale: Locale): string {
  return routes[pageKey][locale];
}

export function pageFor(locale: Locale, pageKey: PageKey): PageContent {
  return content[locale][pageKey];
}

export function routeToSlug(path: string): string | undefined {
  const slug = path.replace(/^\/+|\/+$/g, "");
  return slug === "" ? undefined : slug;
}

export function localizedAlternates(pageKey: PageKey): Array<{ locale: Locale; href: string }> {
  return (Object.keys(localeNames) as Locale[]).map((locale) => ({
    locale,
    href: routeFor(pageKey, locale)
  }));
}

export function staticPages(): Array<{ locale: Locale; pageKey: PageKey; slug: string | undefined }> {
  return (Object.keys(localeNames) as Locale[]).flatMap((locale) =>
    orderedPageKeys.map((pageKey) => ({
      locale,
      pageKey,
      slug: routeToSlug(routeFor(pageKey, locale))
    }))
  );
}
