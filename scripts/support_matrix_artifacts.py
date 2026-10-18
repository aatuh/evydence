#!/usr/bin/env python3
"""Read-only drift checks for build selections; these are not test receipts."""
from pathlib import Path
import os
import re
import stat

import yaml


ARTIFACTS = (
    "go.mod", "tools/go.mod", "tools/go.sum", "Makefile", "Dockerfile", "deploy/local-dependencies/Dockerfile",
    ".github/workflows/ci.yml", ".github/workflows/container-image.yml",
    ".github/workflows/release-artifacts.yml", "README.md",
    "docs/reference/toolchain-platform-support.md",
)
MAX_ARTIFACT_BYTES = 512 * 1024
START = "<!-- BEGIN GENERATED SUPPORT MATRIX -->"
END = "<!-- END GENERATED SUPPORT MATRIX -->"


class UniqueLoader(yaml.BaseLoader):
    """GitHub's YAML scalars stay strings (including the `on` key)."""
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("invalid workflow mapping")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def render_matrix(policy):
    lines = [START, "| Go role | Exact version |", "| --- | --- |",
             f'| Minimum | `{policy["go"]["minimum"]}` |',
             f'| Current | `{policy["go"]["current"]}` |', "",
             "| Platform | CLI target | Server target | Runtime target |",
             "| --- | --- | --- | --- |"]
    release = policy["release"]
    for target in release["cli_targets"]:
        server = "API, worker, migrations" if target in release["server_targets"] else "none"
        runtime = "yes" if target in release["runtime_targets"] else "cross-build only"
        lines.append(f"| `{target}` | `evydence` | {server} | {runtime} |")
    lines += ["", "| QA tool | Exact version | Linux amd64 archive SHA-256 |",
              "| --- | --- | --- |"]
    for name, tool in policy["tools"].items():
        digest = tool.get("linux_amd64_sha256", "Go module checksum database")
        lines.append(f'| `{name}` | `{tool["version"]}` | `{digest}` |')
    lines += ["", "| QA build dependency | Exact version |", "| --- | --- |"]
    for name, version in policy["tool_build_dependencies"].items():
        lines.append(f"| `{name}` | `{version}` |")
    lines += ["", "| SDK language | Delivery |", "| --- | --- |"]
    for language, delivery in policy["sdk"].items():
        lines.append(f"| {language} | `{delivery}` |")
    return "\n".join(lines + [END])


def read_artifact(root, name):
    # The file list is closed and code-owned, not a user-supplied path.
    path = Path(root) / name
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("artifact is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("artifact is not a regular file")
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        with stream:
            data = stream.read(MAX_ARTIFACT_BYTES + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact too large")
    return data.decode("utf-8")


def check_artifacts(policy, *, root=None, read_text=None):
    if read_text is None:
        read_text = lambda name: read_artifact(root, name)
    sources, failures = {}, []
    for name in ARTIFACTS:
        try:
            source = read_text(name)
            if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_ARTIFACT_BYTES:
                raise ValueError("invalid artifact")
            sources[name] = source
        except (OSError, KeyError, ValueError, UnicodeError):
            failures.append(name + ": unreadable or invalid artifact")
    if failures:
        return failures

    def check(condition, diagnostic):
        if not condition:
            failures.append(diagnostic)

    minimum, current = policy["go"]["minimum"], policy["go"]["current"]
    check(re.findall(r"^go\s+(\S+)\s*$", sources["go.mod"], re.M) == [minimum], "go.mod: minimum drift")
    check(re.findall(r"^toolchain\s+(\S+)\s*$", sources["go.mod"], re.M) == ["go" + current], "go.mod: preferred toolchain drift")
    make = sources["Makefile"]
    defaults = {"GOTOOLCHAIN": "go" + current}
    for key, value in defaults.items():
        check(re.findall(r"^" + key + r"\s*\?=\s*(\S+)\s*$", make, re.M) == [value], "Makefile: " + key + " drift")
        assignments = re.findall(r"^(?:(?:export|override)\s+)?" + key + r"\s*([?:+!]?=)", make, re.M)
        check(assignments == ["?="], "Makefile: conflicting " + key + " assignments")
    check("export GOTOOLCHAIN\n" in make, "Makefile: toolchain not exported")

    tool_mod = sources["tools/go.mod"]
    check(re.findall(r"^go\s+(\S+)\s*$", tool_mod, re.M) == [minimum], "tools/go.mod: minimum drift")
    check(re.findall(r"^toolchain\s+(\S+)\s*$", tool_mod, re.M) == ["go" + current], "tools/go.mod: preferred compiler drift")
    check(not re.search(r"^\s*(?:replace|exclude)\b", tool_mod, re.M), "tools/go.mod: dependency graph override")
    tool_packages = {
        "golangci_lint": ("github.com/golangci/golangci-lint/v2", "cmd/golangci-lint"),
        "gosec": ("github.com/securego/gosec/v2", "cmd/gosec"),
        "govulncheck": ("golang.org/x/vuln", "cmd/govulncheck"),
    }
    expected_modules = {module: policy["tools"][name]["version"] for name, (module, _) in tool_packages.items()}
    expected_modules.update(policy["tool_build_dependencies"])
    # go mod tidy validates/canonicalizes this module; drift checks require the
    # canonical dependency bindings and prohibit replacement/exclusion bypasses.
    for module, version in expected_modules.items():
        matches = re.findall(r"^\s+" + re.escape(module) + r" (\S+)(?: // indirect)?$", tool_mod, re.M)
        check(matches == [version], "tools/go.mod: pinned dependency drift")
        check(re.search(r"^" + re.escape(module + " " + version) + r" h1:[A-Za-z0-9+/=]+$", sources["tools/go.sum"], re.M) is not None,
              "tools/go.sum: missing pinned module checksum")
    for module, command in tool_packages.values():
        package = module + "/" + command
        check(re.search(r"^\s+" + re.escape(package) + r"$", tool_mod, re.M) is not None, "tools/go.mod: missing tool declaration")
        check("GOWORK=off $(GO) -C tools install -mod=readonly " + package in make, "Makefile: tool installation bypasses locked graph")

    bases = []
    runtimes = []
    for name in ("Dockerfile", "deploy/local-dependencies/Dockerfile"):
        source = sources[name]
        images = re.findall(r"^FROM (golang:\S+) AS \S+$", source, re.M)
        check(len(images) == 1 and re.fullmatch(r"golang:" + re.escape(current) + r"-alpine3\.23@sha256:[a-f0-9]{64}", images[0]) is not None,
              name + ": Go builder version or immutable digest drift")
        check(re.search(r"^ENV GOTOOLCHAIN=local(?:\s|$)", source, re.M) is not None, name + ": implicit toolchain switching")
        bases += images
        runtime = re.findall(r"^FROM (alpine:\S+)(?: AS \S+)?$", source, re.M)
        check(bool(runtime) and all(re.fullmatch(r"alpine:3\.23@sha256:[a-f0-9]{64}", image) for image in runtime), name + ": unpinned runtime")
        runtimes += runtime
    check(len(set(bases)) == 1, "Dockerfiles: Go builder digest disagreement")
    check(len(set(runtimes)) == 1, "Dockerfiles: runtime digest disagreement")

    workflows = {}
    for name in ARTIFACTS:
        if not name.endswith(".yml"):
            continue
        try:
            workflow = yaml.load(sources[name], Loader=UniqueLoader)
            if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
                raise ValueError("invalid workflow")
            workflows[name] = workflow
            setup_jobs = []
            for key, job in workflow["jobs"].items():
                for step in job.get("steps", []):
                    if str(step.get("uses", "")).startswith("actions/setup-go@"):
                        setup_jobs.append(key)
                        settings = step.get("with", {})
                        if key == "go-compatibility" and name.endswith("/ci.yml"):
                            check(settings.get("go-version") == "${{ matrix.go }}" and "go-version-file" not in settings, name + ": compatibility compiler drift")
                        else:
                            check(settings.get("go-version-file") == "go.mod" and "go-version" not in settings, name + ": preferred compiler drift")
                            # This pinned setup-go version falls back to the go
                            # directive when its incoming environment is local.
                            incoming = step.get("env", {}).get("GOTOOLCHAIN", job.get("env", {}).get("GOTOOLCHAIN", workflow.get("env", {}).get("GOTOOLCHAIN")))
                            check(incoming != "local", name + ": version-file setup can select the minimum compiler")
            expected = {
                ".github/workflows/ci.yml": ["production-check", "race-and-stress", "go-compatibility"],
                ".github/workflows/container-image.yml": ["publish-image", "sign-image"],
                ".github/workflows/release-artifacts.yml": ["package"],
            }
            check(sorted(setup_jobs) == sorted(expected[name]), name + ": missing or duplicate compiler setup")
        except (yaml.YAMLError, ValueError, TypeError, AttributeError, RecursionError):
            failures.append(name + ": invalid workflow")
    try:
        ci = workflows[".github/workflows/ci.yml"]["jobs"]
        check(ci["production-check"]["name"] == "Production Check" and ci["race-and-stress"]["name"] == "Race and Stress", "CI: required check names changed")
        compatibility = ci["go-compatibility"]
        check(compatibility["strategy"]["matrix"]["go"] == list(dict.fromkeys((minimum, current))), "CI: minimum/current matrix drift")
        check(set(compatibility["strategy"]["matrix"]) == {"go"} and compatibility["strategy"].get("fail-fast") == "false" and "if" not in compatibility,
              "CI: compatibility versions can be excluded")
        check(compatibility["env"]["GOTOOLCHAIN"] == "local", "CI: compatibility compiler can switch implicitly")
        check(all(step.get("env", {}).get("GOTOOLCHAIN", "local") == "local" for step in compatibility["steps"]), "CI: step overrides compatibility compiler")
        check(any(step.get("run") == "go version\ngo test ./... -timeout=30m\n" for step in compatibility["steps"]), "CI: incomplete or unbounded compatibility tests")
        envs = [step.get("env", {}) for step in ci["production-check"]["steps"]]
        for tool, version_key, digest_key in (("helm", "HELM_VERSION", "HELM_SHA256"), ("oasdiff", "OASDIFF_VERSION", "OASDIFF_SHA256")):
            check(sum(env.get(version_key) == policy["tools"][tool]["version"] and env.get(digest_key) == policy["tools"][tool]["linux_amd64_sha256"] for env in envs) == 1,
                  "CI: " + tool + " version/checksum drift")
    except (KeyError, TypeError, AttributeError):
        failures.append("CI: missing required toolchain/QA structure")

    check(re.findall(r"--platform ([a-z0-9/,]+)", sources[".github/workflows/container-image.yml"]) == [",".join(policy["release"]["runtime_targets"])],
          "container workflow: runtime platform drift")

    badge = f"https://img.shields.io/badge/go-{minimum}%20%2F%20{current}-00ADD8.svg"
    check(badge in sources["README.md"] and sources["README.md"].count("img.shields.io/badge/go-") == 1, "README.md: Go version badge drift")
    doc = sources["docs/reference/toolchain-platform-support.md"]
    check(doc.count(START) == 1 and doc.count(END) == 1 and render_matrix(policy) in doc, "support reference: generated matrix drift")
    return failures
