# Release Withdrawal Procedure

This how-to is for a maintainer responding to a broken, compromised or withdrawn
Evydence release. It changes release selection and public guidance while
preserving historical evidence. It does not itself revoke a credential, publish
an advisory or establish release security.

## Record And Review The Decision

Use [SECURITY.md](../../SECURITY.md) for private security intake. Keep credentials,
private evidence and exploit details out of public withdrawal reasons. Follow
[signing custody and incident response](../release-signing.md) if signing identity
or publisher credentials may be compromised; a tag withdrawal and signing-source
revocation have different scopes.

Append an entry to `withdrawals` in
[`release/lifecycle-policy.json`](../../release/lifecycle-policy.json). Keep every
existing entry. Record the exact tag, its original 40-character source commit,
UTC decision timestamp, a sanitized public reason and a notice URL under the
repository's GitHub releases, issues or security advisories. `replacement_tag`
is either a different, non-withdrawn tag or `null`.

For example, this is synthetic schema data, not an actual withdrawal:

```json
{
  "tag": "v9.9.9-rc.1",
  "source_commit": "1111111111111111111111111111111111111111",
  "recorded_at": "2000-01-01T00:00:00Z",
  "reason": "Synthetic example: use the reviewed upgrade path.",
  "notice_url": "https://github.com/aatuh/evydence/releases/tag/v9.9.9-rc.1",
  "replacement_tag": null
}
```

Every committed withdrawal is immediately effective. Timestamps are historical
records, not a scheduler. Duplicate entries, invalid identifiers or timestamps,
control characters, unsupported notice locations and withdrawn replacements
are rejected. The validator checks syntax and consistency; it does not prove
that a notice was published or a replacement exists.

## Update Selection And Guidance

1. Resolve the tag's original source before recording it. Do not retag the same
   version or replace its original artifacts, signatures, manifests or checksums.
2. If the selected current release is withdrawn, default selection fails closed.
   `replacement_tag` is advisory and never silently changes the selected release.
   Promote only a separately verified replacement through
   [`release/current.json`](../../release/current.json) and the canonical install
   and release-evidence docs. With no replacement, leave default installation
   unavailable and explain that state publicly.
3. Regenerate the reference and run the checks below. A withdrawn current release
   remains valid history and can pass the policy/reference checks. The
   `default-tag` command stays failed until a non-withdrawn release is selected.
   With no replacement, all four canonical install guides (README, getting
   started, ten-minute evaluation and install/operate) must say
   `No default install is available.`, identify the tag as `WITHDRAWN`, and remove
   its download, install-path and verification command examples. Release-truth
   checks enforce that state so an emergency withdrawal can merge without
   inventing a replacement release.
4. Have the change reviewed under the
   [maintainer review policy](maintainer-review-policy.md). The JSON file is not
   evidence of independent review or of provider-side enforcement.

```sh
python3 scripts/release_lifecycle.py render > docs/reference/release-support.md
make release-lifecycle-check
python3 scripts/check_release_truth.py
```

The shared host RAM protocol still applies to any memory-intensive project
checks. See [release validation](release-validation.md) for the broader release
gate. `scripts/public_release_verify.sh` rejects registered withdrawn tags before
downloads; `scripts/release_candidate_package.sh` rejects them before builds,
signing-key processing or release-directory replacement. A lifecycle check does
not replace publisher/signature, checksum, compatibility or operator review.

## Announce And Preserve History

After approval, the release owner must update the existing public release notes
to start with a prominent **WITHDRAWN** warning and link the sanitized notice and
verified replacement, if any. Remove the release from the provider's default or
latest selection. Keep its historical tag, assets and evidence available with
the warning. Update install guidance and announce through the project's existing
support/security channels; do not claim those external actions happened merely
because the repository JSON changed.

Provider changes and announcements require the owner's authorization. These local
tools do not perform them. Record their actual links, dates and owner evidence
before claiming the response is complete. For a compromised release, preserve
private investigation evidence separately and rotate or revoke affected signing
or publishing identities through the canonical incident procedure.
