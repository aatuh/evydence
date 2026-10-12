# Scanner fixture provenance

Each `*.json` report is a minimized, synthetic/sanitized fixture retaining the
field names and nesting exercised by the named tool; no customer payload or
scanner credential is included. The matching `*.golden.json` is the expected
Evydence projection, not source output.

- Grype: `anchore/grype` JSON printer (`matches[].vulnerability` and
  `matches[].artifact`), as also used by `scripts/github_release_evidence_manifest.py`.
- Trivy: `aquasecurity/trivy` JSON result (`Results[].Vulnerabilities[]` and
  `PkgIdentifier.PURL`), as also used by the release-manifest generator.
- OSV-Scanner: Google’s maintained
  `internal/output/__snapshots__/machinejson_test.snap`, particularly
  `results[].packages[].vulnerabilities[]` and severity score-array shape.
- Dependency-Track: its exported finding boundary is represented by a
  component PURL plus vulnerability `vulnId`, source, severity, state, and
  fixed version. The adapter deliberately requires this explicit scoped
  finding shape rather than guessing a project-wide API response.

These adapters preserve raw payload bytes. They normalize only documented
fields and do not assert that a scanner result is complete or authoritative.
