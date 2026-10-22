# Trusted Dependency Source Collection

This reference is for maintainers connecting PR source to dependency admission.
`scripts/dependency_collection.py` uses trusted Python and a
[base-built classifier](dependency-classifier.md) to collect source observations
from [verified Git input bytes](dependency-inputs.md). Proposed Python, Go helper
code, shell recipes and package lifecycle scripts are never executed by this
entry point.

The report keeps `dependency_coverage_verified: false`. Image collection,
complete license/advisory coverage, trusted policy selection and hosted admission
remain separate work under EVY-1407. A successful source observation is not
license approval, a vulnerability-free result or a passing hosted PR check.

## Data And Executable Sources

The caller runs this script and its imports from a trusted checkout. The selected
source commit supplies Git-verified regular blobs. Missing required inputs or
unclassified manifests fail before classifier builds or registry collection.
Paths, byte counts, Git blob IDs and SHA-256 values are checked again at export.
Files are copied into a fresh private directory with mode 0600; source scripts
have no executable permission. No checkout or owner working-tree edit is used.

The classifier is built from the explicitly selected trusted base, with its own
QA locks and support policy. Proposed QA locks describe the proposed dependency
graph and cannot replace the executable helper's build dependencies. Proposed
compiler selection must match the base-built classifier. Go graph commands use
isolated manifest copies, public proxy/checksum configuration and the helper's
private credential-free environment. npm/Python archives, build tools, fixtures
and Action sources use the existing bounded structured collectors without
package installation or execution.

`dependency_inventory.collect(..., classifier=artifact)` records trusted Python
generator hashes and the base helper's actual Go source hashes, plus the helper
receipt. Proposed manifests remain separate input hashes. It does not import
Python or build Go code from the proposed source directory. The standalone
inventory command retains its existing operator-trusted local source behavior;
use this Git collection entry point for proposed PR data.

Before returning observations, the caller verifies all exported files again,
rejects added files or symlinks, checks the built executable and confirms trusted
Python source bytes stayed unchanged. Owner changes are preserved and cause a
failure. Reports include immutable source metadata, trusted driver hashes and
inventory observations; source bodies, credentials, private paths and raw tool
diagnostics are omitted. Private scratch/log directories remain for diagnosis.

## PR Context And Local Use

For a live PR, the authenticated provider reader checks the expected current
target base, head and head repository before collection. The helper uses that
current target base, independently of the comparison's merge base. The live PR
is checked again after collection and before atomic output. A changed context
fails without writing an observation. Provider access remains in trusted Python;
collector/classifier subprocesses do not receive its credentials.

Local mode accepts explicit immutable source/base IDs. It proves byte identity
and tooling selection, not GitHub authorization or review. The caller must select
a reviewed base and the installed compiler/cache configuration. Use an existing
VM scratch directory and a suitable RAM reservation:

```sh
"$HOME/.local/bin/codex-ramgate" 4 -- python3 scripts/dependency_collection.py \
  --local-repository . \
  --trusted-base "$EVYDENCE_REVIEWED_BASE" --source "$EVYDENCE_SOURCE_COMMIT" \
  --work-root /mnt/vm-storage/VMs/evydence-dev-1001/tmp \
  --output tmp/takeover/dependency-collection.json
```

For authenticated PR mode, replace `--local-repository` with `--pull-request N`
and supply `--head-repository OWNER/REPO`. The expected source/base IDs remain
required. Source reads and heavy subprocesses stay serial. `--replace` permits
only matching-schema report replacement and protects concurrent output edits.
Exit 0 means a source observation was written; exit 2 means source, tooling,
provider context or output validation failed.

`make dependency-collection-test` runs isolated caller regressions without real
provider/build operations. Collector trust-boundary cases also run in
`make dependency-inventory-test`; both are included in `make docs-check`.
Source collection does not add a GitHub workflow, change branch protection,
approve an exception, push or publish anything.

## Local Qualification

On 2026-10-22, a real collection from source/base
`40e26f443f28a43fec8115ad831ecc3f38339c8c` verified 163 selected Git inputs and
preserved all 2,880 prior component observations. The saved primary inventory
was projected from that run; image and maintenance companions were regenerated
through their actual collectors. These are local observations of selected
sources and artifact profiles, with their existing coverage limits.

The older public PR #30 was also checked through the real authenticated caller.
It returned 2 for its five known missing inputs before any classifier build and
without writing a collection report. This is a verified rejection of incomplete
older source, not a passing current hosted check or complete admission verdict.
