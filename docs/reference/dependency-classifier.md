# Trusted Dependency License Classifier

This reference is for maintainers connecting dependency admission to PR data.
`scripts/dependency_classifier.py` builds the existing bounded license helper
from an explicitly selected trusted base commit. The Python implementation and
its imports must also run from a trusted checkout. Proposed source supplies data;
it must never replace the code or dependencies used to build this helper.

The caller must bind `trusted_base` to the PR's current reviewed target base,
separately from the input comparison's merge base. A valid Git ID proves source
identity, not review or authorization. The builder does not make that provider
decision, install a workflow or establish complete dependency admission.

## Source And Build Boundary

The builder reads Git objects through the [immutable reader](dependency-inputs.md).
It selects only base `tools/go.mod`, `tools/go.sum`,
`release/support-matrix.json` and non-test Go source in
`tools/cmd/license-inventory/`. Every selected file must be a regular blob with
matching bytes and identity. Unexpected helper assets/subdirectories fail;
supporting another source layout requires an explicit implementation change.
At most 64 files and 4 MiB of source are accepted, with the reader's separate
1 MiB per-blob bound. No working-tree checkout, owner edit or PR script is used.

Sources are copied into a fresh private directory under the operator's scratch
root. The Go toolchain must exactly match the base support policy's current
version. Go's structured manifest output must identify the QA module with no
replacement or exclusion overrides. The only package built is
`./cmd/license-inventory`; test files, tool directives, generators and proposed
package scripts are not run.

The serial build uses `-mod=readonly`, `-trimpath`, `-buildvcs=false`, disabled
cgo and a fixed public Go proxy/checksum database without direct VCS fallback.
`go mod verify` must exit successfully, and all copied source/lock bytes must
remain unchanged before an artifact is returned. Downloaded Go dependencies
remain subject to Go's [module authentication](https://go.dev/ref/mod#authenticating).
The host toolchain, executable path, configured certificate files and reused
operator caches remain trusted local infrastructure.

Subprocesses have a fresh home and temporary directory. Provider credentials,
ambient Go flags, workspace settings, private-module configuration and netrc
credentials are excluded. `GOAUTH=off` disables module authentication helpers;
`GOVCS=*:off` prevents direct VCS commands. See Go's
[authentication](https://pkg.go.dev/cmd/go#hdr-GOAUTH_environment_variable) and
[VCS controls](https://pkg.go.dev/cmd/go#hdr-Controlling_version_control_with_GOVCS).
Telemetry is disabled in the private home with `go telemetry off` and checked
using `go env GOTELEMETRY`; the host's telemetry configuration is not changed.

The build receipt records the base/tree, selected Git blob IDs and SHA-256
values, compiler/target, fixed recipe and resulting binary digest/size. It omits
source bodies, private filesystem paths, credentials and raw subprocess output.
Private work/log directories remain available for diagnosis after a failure.
An unrelated output file or concurrent output edit cannot be overwritten.

## Classification And Checks

The returned `BuiltClassifier` verifies its executable digest before and after
classification. Each invocation gets a separate private log directory. License
bytes are digest-bound stdin data for the existing bounded helper. Unknown and
ambiguous results remain explicit; a text candidate is not license approval,
legal compatibility or complete dependency coverage.

Run the focused isolated regressions with:

```sh
make dependency-classifier-test
```

They also run under `make docs-check`. They use fake tool results and never
compile or access a provider. For an actual local build, supply a full reviewed
base SHA and an existing VM scratch directory:

```sh
"$HOME/.local/bin/codex-ramgate" 4 -- python3 scripts/dependency_classifier.py \
  --trusted-base "$EVYDENCE_REVIEWED_BASE" \
  --work-root /mnt/vm-storage/VMs/evydence-dev-1001/tmp \
  --output tmp/takeover/classifier-receipt.json
```

The caller configures the appropriate installed compiler and cache locations.
`--local-repository` optionally selects the Git object store. Output is created
exclusively; `--replace` only permits replacing the same report schema, with
concurrent edits protected. Exit 0 means a verified base build receipt was
written; exit 2 means invalid source, failed tooling or unsafe output.

The [Git collection caller](dependency-collection.md) supplies this artifact to
the inventory collector and keeps proposed code as data. The standalone inventory
command retains its operator-trusted local `root/tools` build path; it must not
be run on proposed PR source with provider credentials. Complete component/
license/advisory coverage and trusted policy selection remain incomplete under
EVY-1407. Neither a saved receipt nor these regressions is hosted enforcement.

A local build from `59e6da0e1f3df16d0e216972c651cfab75404af2` with Go 1.27.3
on Linux amd64 passed recognized MIT, mixed-license ambiguous and unknown-text
vectors. The 8,219,123-byte binary has SHA-256
`2be8b0565fe14ee2fa92ba325e6cf5b1240c88850d0beed9cef7387f71b4131e`.
This is local build qualification of the helper, not a current hosted PR verdict.
