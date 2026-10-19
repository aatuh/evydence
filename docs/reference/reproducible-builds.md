# Reproducible release payloads

This reference is for maintainers comparing unsigned release payloads from an
exact source commit. It describes the build recipe and evidence boundaries;
it is not a claim that independent runner qualification has already passed.
The root backlog owns EVY-1402 completion and its actual validation evidence.

## Scope and identity

`scripts/release_build.py` is the shared unsigned build recipe used by candidate
packaging and reproducibility checks. The support matrix selects eight Go
binaries across five platform archives. The comparison requires exactly
**14 outputs**: those eight binaries, five archives, and the pre-build manifest.
It rereads the actual files and checks both their recorded digests and equality.
Matching report text without matching bytes cannot pass.

A successful comparison carries its verified artifact inventory. Candidate
packaging captures that proof in a private temporary file and checks the actual
rebuilt signable archives, binaries and manifest against it. Changed final bytes,
an invalid proof, or a wrong build identity stop packaging before signing. The
operator log records the retained proof path; unrelated ambient compiler inputs
cannot replace the inventory.

The recipe requires a clean checkout of the expected commit and the declared
current Go compiler. It pins CGO off, baseline architecture settings, no optional
Go experiments, workspace configuration off, readonly modules, PGO off, trimmed
paths, VCS auto-injection off, and an empty linker build ID. Build work runs
serially with one Go package build at a time. Compiler children receive an
allowlist of tool/cache paths and fixed build settings; signing credentials,
provider tokens, test database configuration and ambient build flags are omitted.

`release-build-manifest.json` retains schema
`evydence-release-build-manifest.v1` and adds `build_recipe_version` and
`source_date_epoch`. The epoch is the Git commit's committer timestamp.
`build_time`, including the API's immutable build identity, is that fixed UTC
source time. It does **not** measure when the compiler executed. An ambient
`SOURCE_DATE_EPOCH` override does not replace the source-derived value.
Material paths are source-relative and hashes cover the modules, contract,
migrations and build recipe inputs. No local checkout path belongs in the
manifest. Its digest remains a pre-build identity; it does not recursively
claim to be the digest of the final signed manifest containing the binary.

Archives include only the declared executables and `LICENSE`, `README.md`, and
`CHANGELOG.md`; extra files, symlinks and overwrites are rejected. Members are
sorted. Tar ownership is numeric zero with empty owner/group names, fixed source
timestamps, and normalized directory/executable/document modes. Gzip omits the
output filename and uses level 9. Windows ZIP entries have fixed UTC/DOS times,
normalized modes, no extra/comment fields and stored payloads. ZIPs are larger
because their contents are uncompressed. ZIP timestamps have two-second
resolution and clamp pre-1980 source dates to the format's lower bound.

## Local repeatability

With the declared compiler and tools available:

```sh
make release-repro-policy-test
make reproducible-build-check TAG=v0.0.0-rc.1402
```

The first command uses tiny fixtures and fake build/validation programs. It does
not compile Go, contact providers, sign artifacts or start services. The second
creates two detached clean worktrees of the current commit, uses separate fresh
Go build caches, runs the complete shared recipe in each, and compares all 14
outputs. The module cache may be shared; this is repeatability on one host and
does not establish independent hosted runners.

`REPRODUCIBLE_BUILD_ROOT` selects the retained run directory's parent. Its
default is `$TMPDIR/evydence-reproducible-build` when `TMPDIR` is configured,
otherwise `tmp/reproducible-build`. Each attempt creates a fresh `run-*` directory
with bundles, caches and `comparison.json`; existing evidence is preserved.
Choose storage with several GiB available for separate build caches. Successful
worktrees are removed without force. Failed worktrees and outputs remain for
inspection; unexpected source edits are never forcibly removed.

On hosts requiring the shared RAM coordinator, wrap the complete heavy command:

```sh
"$HOME/.local/bin/codex-ramgate" 8 -- \
  make reproducible-build-check TAG=v0.0.0-rc.1402
```

Use the host's declared Go/cache environment before invoking that command. Keep
the reservation while compiler children run and do not start another heavy job
inside it. The tiny policy tests need no heavy-job reservation by themselves.

## Independent runner evidence and release blocking

`.github/workflows/reproducible-builds.yml` creates separate Ubuntu 24.04 matrix
jobs, with Go cache restoration disabled, followed by a comparison job. It runs
on pull requests/default-branch pushes and is reusable by the release workflow.
Build jobs have read-only repository permissions, do not persist checkout
credentials, and receive no signing or publication secret. Artifacts retain the
two unsigned bundles and a dated comparison, including mismatch details.
Python and zlib versions are recorded in each build report for diagnosis.

Signed release packaging depends on successful hosted comparison. The local
candidate script also runs `make reproducible-build-check TAG=<candidate>` after
its normal production gate and before replacing artifacts or signing. A failure
stops the candidate. Production validation and signing are still mandatory;
the unsigned build command is not a replacement for either.

The final payload binding can also be checked without building:

```sh
python3 scripts/reproducible_build.py verify-candidate \
  --tag v0.0.0-rc.1402 --expected-commit <full-source-commit> \
  --archives dist/v0.0.0-rc.1402 --work tmp/release-candidate/v0.0.0-rc.1402 \
  --comparison <successful-comparison.json>
```

Comparison reports from before the verified-inventory field was introduced are
not sufficient for this signing precondition. Preserve historical artifacts and
run a fresh comparison for new candidate packaging.

To examine downloaded bundles without compiling:

```sh
python3 scripts/reproducible_build.py compare \
  --tag v0.0.0-rc.1402 --expected-commit <full-source-commit> \
  --first <first-bundle> --second <second-bundle> \
  --output <new-comparison.json>
```

The comparator exits `0` for complete equality, `1` for differences, and `2` for
invalid command inputs or execution failure. Reports reject duplicate JSON keys,
oversized input, traversal or unexpected artifact records, missing files and
symlinks. Diff reports contain only allowlisted paths and fixed diagnostic codes.
Reports are limited to 2 MiB and each artifact to 1 GiB. Source epochs use the
nonnegative 32-bit range required by the gzip timestamp field.

A passing comparison authenticates neither runner identity nor provenance.
Before closing EVY-1402, retain actual GitHub workflow/run and distinct build-job
IDs, the exact checkout commit, both bundles and the successful comparison.
Verify provider job results; two local runs or invented runner labels are
insufficient. See GitHub's [reusable workflow semantics](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
for how the release workflow calls the comparison at its own source commit.

## Excluded evidence and compatibility

This scope excludes OCI image/layer digests, native execution on non-Linux
platforms, coverage profiles, dated validation summaries, provider run metadata,
SBOM/provenance documents and final signed manifests/signatures. Those records
describe an execution or signer and can differ between runs; they remain checked
and signed by the normal release-candidate gate. Container publication has a
separate recipe and qualification. Historical published assets and their
original compiler commitments remain unchanged.

Equality is measured for the exact source, compiler, recipe and compared outputs;
it is not a universal promise across arbitrary toolchain or compressor versions.
Reproducibility does not prove that source, dependencies, builder or signing
identity are trustworthy, or provide compliance or certification conclusions.
