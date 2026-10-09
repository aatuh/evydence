#!/usr/bin/env python3
"""Validate the EVY-902 context-owned domain model split."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
ADR = ROOT / "docs" / "adr" / "0003-bounded-contexts.md"
LEGACY_DOMAIN = ROOT / "internal" / "domain"

CONTEXT_PATHS = {
    "Identity and access": "identity",
    "Release catalog": "release",
    "Evidence ingestion": "evidence",
    "Vulnerability decisions and governance": "risk",
    "Package and reporting": "package",
    "Verification and signing": "verification",
    "Operations and incidents": "operations",
    "Integration ingestion": "integration",
    "Experimental peripherals": "experimental",
}

SUPPORT_TYPES = {
    "identity": {"VerificationCheck", "VerificationProfileSnapshot"},
    "release": {"ReleaseCandidateState", "ReleaseState"},
    "evidence": {"EvidenceLifecycleState", "CanonicalEvidenceOrigin"},
    "risk": {"DecisionStatus", "SupportingReference", "ReadinessSnapshot"},
    "package": {
        "AcceptedExceptionSnapshot",
        "BundleState",
        "ControlEvidenceSnapshot",
        "IncidentSnapshot",
        "IncidentTimelineEventSnapshot",
        "PolicyCheckSnapshot",
        "RemediationTaskSnapshot",
        "SupportingReference",
        "VulnerabilityDecisionSnapshot",
    },
    "verification": {
        "SigningKeyStatus",
        "VerificationProfile",
        "VerificationProfileDefinition",
        "VerificationState",
    },
    "operations": {"IncidentStatus"},
    "integration": {"CollectorStatus", "VerificationCheck"},
    "experimental": {"VerificationCheck"},
}

FIELD_TYPE_OVERRIDES = {
    ("identity", "ProviderVerification", "Checks"): "[]VerificationCheck",
    ("identity", "ProviderVerification", "Profile"): "VerificationProfileSnapshot",
    ("release", "Release", "State"): "ReleaseState",
    ("release", "ReleaseCandidate", "State"): "ReleaseCandidateState",
    ("evidence", "EvidenceLifecycleEvent", "Action"): "EvidenceLifecycleState",
    ("risk", "VulnerabilityDecision", "Status"): "DecisionStatus",
    ("risk", "VulnerabilityDecision", "SupportingRefs"): "[]SupportingReference",
    ("risk", "VulnerabilityDecisionCustomerSummary", "SupportingRefs"): "[]SupportingReference",
    ("package", "CRAReadinessReport", "AcceptedExceptions"): "[]AcceptedExceptionSnapshot",
    ("package", "CRAVulnerabilityHandlingReport", "AcceptedExceptions"): "[]AcceptedExceptionSnapshot",
    ("package", "CRAVulnerabilityHandlingReport", "Decisions"): "[]VulnerabilityDecisionSnapshot",
    ("package", "ControlCoverageItem", "LinkedEvidence"): "[]ControlEvidenceSnapshot",
    ("package", "ControlCoverageReport", "AcceptedExceptions"): "[]AcceptedExceptionSnapshot",
    ("package", "IncidentReport", "Tasks"): "[]RemediationTaskSnapshot",
    ("package", "IncidentReport", "Timeline"): "[]IncidentTimelineEventSnapshot",
    ("package", "ReleaseBundle", "State"): "BundleState",
    ("package", "ReleaseReadinessReport", "AcceptedExceptions"): "[]AcceptedExceptionSnapshot",
    ("package", "ReleaseReadinessReport", "Checks"): "[]PolicyCheckSnapshot",
    ("package", "SecurityUpdateEvidenceReport", "FixedDecisions"): "[]VulnerabilityDecisionSnapshot",
    ("package", "SecurityUpdateEvidenceReport", "Incidents"): "[]IncidentSnapshot",
    ("package", "SecurityUpdateEvidenceReport", "RemediationTasks"): "[]RemediationTaskSnapshot",
    ("verification", "SigningKey", "Status"): "SigningKeyStatus",
    ("verification", "VerificationResult", "Result"): "VerificationState",
    ("operations", "Incident", "Status"): "IncidentStatus",
    ("integration", "Collector", "Status"): "CollectorStatus",
    ("integration", "CollectorHealthReport", "Checks"): "[]VerificationCheck",
    ("experimental", "MarketplaceCollectorHealthReport", "Checks"): "[]VerificationCheck",
    ("experimental", "PublicTransparencyLogEntry", "VerificationChecks"): "[]VerificationCheck",
}

OMITTED_CONTEXT_FIELDS = {
    ("verification", "SigningKey", "Private"),
}

LEGACY_ALIAS_TYPES = {"Actor", "ResourceGrant"}

SUPPORT_MODEL_SOURCES = {
    ("identity", "VerificationCheck"): "VerifyCheck",
    ("identity", "VerificationProfileSnapshot"): "VerificationProfile",
    ("risk", "SupportingReference"): "SubjectRef",
    ("package", "AcceptedExceptionSnapshot"): "Exception",
    ("package", "ControlEvidenceSnapshot"): "ControlEvidence",
    ("package", "IncidentSnapshot"): "Incident",
    ("package", "IncidentTimelineEventSnapshot"): "IncidentTimelineEvent",
    ("package", "PolicyCheckSnapshot"): "PolicyCheck",
    ("package", "RemediationTaskSnapshot"): "RemediationTask",
    ("package", "SupportingReference"): "SubjectRef",
    ("package", "VulnerabilityDecisionSnapshot"): "VulnerabilityDecisionCustomerSummary",
    ("integration", "VerificationCheck"): "VerifyCheck",
    ("experimental", "VerificationCheck"): "VerifyCheck",
}

SUPPORT_MODEL_FIELD_OVERRIDES = {
    ("package", "VulnerabilityDecisionSnapshot", "SupportingRefs"): "[]SupportingReference",
}

STABLE_FIELD_TYPES = {
    "release": {
        "Release": ("State", "ReleaseState"),
        "ReleaseCandidate": ("State", "ReleaseCandidateState"),
    },
    "evidence": {
        "EvidenceLifecycleEvent": ("Action", "EvidenceLifecycleState"),
    },
    "risk": {
        "VulnerabilityDecision": ("Status", "DecisionStatus"),
    },
    "package": {
        "ReleaseBundle": ("State", "BundleState"),
    },
    "verification": {
        "SigningKey": ("Status", "SigningKeyStatus"),
        "VerificationResult": ("Result", "VerificationState"),
    },
    "operations": {
        "Incident": ("Status", "IncidentStatus"),
    },
    "integration": {
        "Collector": ("Status", "CollectorStatus"),
    },
}

REQUIRED_MAPPERS = {
    "ActorToIdentityModel",
    "ActorFromIdentityModel",
    "ReleaseToContextModel",
    "ReleaseFromContextModel",
    "SubjectRefToEvidenceModel",
    "SubjectRefFromEvidenceModel",
    "VulnerabilityDecisionToContextModel",
    "VulnerabilityDecisionFromContextModel",
    "ReleaseBundleToContextModel",
    "ReleaseBundleFromContextModel",
    "VerificationResultToContextModel",
    "VerificationResultFromContextModel",
    "IncidentToContextModel",
    "IncidentFromContextModel",
    "CollectorToContextModel",
    "CollectorFromContextModel",
}

TYPE_PATTERN = re.compile(r"(?m)^type\s+([A-Z][A-Za-z0-9_]*)\b")
STRUCT_PATTERN = re.compile(
    r"(?ms)^type\s+([A-Z][A-Za-z0-9_]*)\s+struct\s*\{(.*?)^\}"
)
CONST_BLOCK_PATTERN = re.compile(r"(?ms)^const\s*\((.*?)^\)")
CONST_LINE_PATTERN = re.compile(r"(?m)^\s*([A-Z][A-Za-z0-9_]*)\b")
SINGLE_CONST_PATTERN = re.compile(r"(?m)^const\s+([A-Z][A-Za-z0-9_]*)\b")
SINGLE_IMPORT_PATTERN = re.compile(
    r'(?m)^import[ \t]+(?:[._A-Za-z][A-Za-z0-9_]*[ \t]+)?"([^"]+)"'
)
IMPORT_BLOCK_PATTERN = re.compile(r"(?ms)^import[ \t]*\(\s*(.*?)^[ \t]*\)")
IMPORT_ENTRY_PATTERN = re.compile(
    r'(?m)^[ \t]*(?:[._A-Za-z][A-Za-z0-9_]*[ \t]+)?"([^"]+)"'
)


def imported_packages(body: str) -> list[str]:
    packages = SINGLE_IMPORT_PATTERN.findall(body)
    for block in IMPORT_BLOCK_PATTERN.findall(body):
        packages.extend(IMPORT_ENTRY_PATTERN.findall(block))
    return packages


def parse_adr_ownership(body: str) -> dict[str, set[str]]:
    ownership = {path: set() for path in CONTEXT_PATHS.values()}
    for line in body.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[0] not in CONTEXT_PATHS:
            continue
        context = CONTEXT_PATHS[cells[0]]
        ownership[context].update(re.findall(r"`([A-Z][A-Za-z0-9_]*)`", cells[1]))
    return ownership


def declared_types(body: str) -> set[str]:
    return set(TYPE_PATTERN.findall(body))


def declared_struct_fields(body: str) -> dict[str, dict[str, str]]:
    models: dict[str, dict[str, str]] = {}
    for name, struct_body in STRUCT_PATTERN.findall(body):
        fields: dict[str, str] = {}
        for raw_line in struct_body.splitlines():
            line = raw_line.split("`", 1)[0].strip()
            if not line or line.startswith("//"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2 or not re.fullmatch(r"[A-Z][A-Za-z0-9_]*", parts[0]):
                continue
            fields[parts[0]] = parts[1].strip()
        models[name] = fields
    return models


def context_field_compatibility_failures(
    context: str,
    owned: set[str],
    legacy_models: dict[str, dict[str, str]],
    context_models: dict[str, dict[str, str]],
) -> list[str]:
    failures: list[str] = []
    for model in sorted(owned & legacy_models.keys() & context_models.keys()):
        expected = {}
        for field, field_type in legacy_models[model].items():
            if (context, model, field) in OMITTED_CONTEXT_FIELDS:
                continue
            expected[field] = FIELD_TYPE_OVERRIDES.get(
                (context, model, field), field_type
            )
        actual = context_models[model]
        if actual != expected:
            missing = sorted(expected.keys() - actual.keys())
            unexpected = sorted(actual.keys() - expected.keys())
            changed = sorted(
                field
                for field in expected.keys() & actual.keys()
                if expected[field] != actual[field]
            )
            details = []
            if missing:
                details.append("missing fields " + ", ".join(missing))
            if unexpected:
                details.append("unexpected fields " + ", ".join(unexpected))
            if changed:
                details.append(
                    "changed field types "
                    + ", ".join(
                        f"{field} ({expected[field]} -> {actual[field]})"
                        for field in changed
                    )
                )
            failures.append(
                f"internal/{context}/domain: {model} compatibility mismatch: "
                + "; ".join(details)
            )
    return failures


def support_model_compatibility_failures(
    context: str,
    legacy_models: dict[str, dict[str, str]],
    context_models: dict[str, dict[str, str]],
) -> list[str]:
    failures: list[str] = []
    for (owner, model), source in SUPPORT_MODEL_SOURCES.items():
        if owner != context:
            continue
        if source not in legacy_models or model not in context_models:
            failures.append(
                f"internal/{context}/domain: cannot compare {model} with legacy {source}"
            )
            continue
        expected = {
            field: SUPPORT_MODEL_FIELD_OVERRIDES.get(
                (context, model, field), field_type
            )
            for field, field_type in legacy_models[source].items()
        }
        if context_models[model] != expected:
            failures.append(
                f"internal/{context}/domain: {model} must match legacy {source} fields"
            )
    return failures


def declared_constants(body: str) -> set[str]:
    constants = set(SINGLE_CONST_PATTERN.findall(body))
    for block in CONST_BLOCK_PATTERN.findall(body):
        constants.update(CONST_LINE_PATTERN.findall(block))
    return constants


def source_boundary_failures(relative_path: str, body: str) -> list[str]:
    failures: list[str] = []
    for tag in ("`json:", "`db:", "`yaml:", "`form:"):
        if tag in body:
            failures.append(f"{relative_path}: transport or persistence tag {tag!r} is forbidden")
    for imported in imported_packages(body):
        if "." in imported.split("/")[0] or "/internal/" in imported:
            failures.append(f"{relative_path}: domain imports non-standard package {imported}")
    return failures


def legacy_constants(root: pathlib.Path) -> set[str]:
    constants: set[str] = set()
    for path in sorted((root / "internal" / "domain").glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        constants.update(declared_constants(path.read_text(encoding="utf-8")))
    return constants


def context_sources(root: pathlib.Path, context: str) -> list[pathlib.Path]:
    directory = root / "internal" / context / "domain"
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.glob("*.go") if not path.name.endswith("_test.go"))


def validate_repository(root: pathlib.Path = ROOT) -> list[str]:
    adr = root / "docs" / "adr" / "0003-bounded-contexts.md"
    if not adr.is_file():
        return ["bounded-context ADR is missing"]
    ownership = parse_adr_ownership(adr.read_text(encoding="utf-8"))
    failures: list[str] = []
    occurrences: dict[str, list[str]] = {}
    constant_occurrences: dict[str, list[str]] = {}
    legacy_body = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((root / "internal" / "domain").glob("*.go"))
        if not path.name.endswith("_test.go")
    )
    legacy_models = declared_struct_fields(legacy_body)

    for context, owned in ownership.items():
        sources = context_sources(root, context)
        if not sources:
            failures.append(f"internal/{context}/domain: context domain package is missing")
            continue
        found: set[str] = set()
        context_body = "\n".join(
            path.read_text(encoding="utf-8") for path in sources
        )
        context_models = declared_struct_fields(context_body)
        for path in sources:
            relative = path.relative_to(root).as_posix()
            body = path.read_text(encoding="utf-8")
            failures.extend(source_boundary_failures(relative, body))
            for name in declared_types(body):
                found.add(name)
                occurrences.setdefault(name, []).append(context)
            for name in declared_constants(body):
                constant_occurrences.setdefault(name, []).append(context)
        expected = owned | SUPPORT_TYPES.get(context, set())
        missing = sorted(expected - found)
        unexpected = sorted(found - expected)
        if missing:
            failures.append(f"internal/{context}/domain: missing types: {', '.join(missing)}")
        if unexpected:
            failures.append(f"internal/{context}/domain: unexpected types: {', '.join(unexpected)}")
        unparsed_legacy_models = sorted(
            owned - legacy_models.keys() - LEGACY_ALIAS_TYPES
        )
        if unparsed_legacy_models:
            failures.append(
                "internal/domain: compatibility structs could not be parsed: "
                + ", ".join(unparsed_legacy_models)
            )
        failures.extend(
            context_field_compatibility_failures(
                context, owned, legacy_models, context_models
            )
        )
        failures.extend(
            support_model_compatibility_failures(
                context, legacy_models, context_models
            )
        )

    all_owned = set().union(*ownership.values())
    for name in sorted(all_owned):
        owners = occurrences.get(name, [])
        expected_owner = next(context for context, names in ownership.items() if name in names)
        if owners != [expected_owner]:
            failures.append(
                f"{name}: expected exactly one declaration in {expected_owner}, found {owners}"
            )

    for constant in sorted(legacy_constants(root)):
        owners = constant_occurrences.get(constant, [])
        if len(owners) != 1:
            failures.append(
                f"{constant}: expected exactly one context schema/behavior declaration, found {owners}"
            )

    for context, expectations in STABLE_FIELD_TYPES.items():
        body = "\n".join(
            path.read_text(encoding="utf-8") for path in context_sources(root, context)
        )
        for model, (field, field_type) in expectations.items():
            model_match = re.search(
                rf"(?ms)^type\s+{re.escape(model)}\s+struct\s*\{{(.*?)^\}}", body
            )
            if not model_match or not re.search(
                rf"(?m)^\s*{re.escape(field)}\s+{re.escape(field_type)}\b",
                model_match.group(1),
            ):
                failures.append(
                    f"internal/{context}/domain: {model}.{field} must use {field_type}"
                )

    mapper_path = root / "internal" / "domain" / "context_compat.go"
    mapper_body = mapper_path.read_text(encoding="utf-8") if mapper_path.is_file() else ""
    mapper_names = declared_function_names(mapper_body)
    missing_mappers = sorted(REQUIRED_MAPPERS - mapper_names)
    if missing_mappers:
        failures.append("legacy context compatibility mappers missing: " + ", ".join(missing_mappers))

    return failures


def declared_function_names(body: str) -> set[str]:
    return set(re.findall(r"(?m)^func\s+([A-Z][A-Za-z0-9_]*)\s*\(", body))


def main() -> int:
    failures = validate_repository()
    if failures:
        for failure in failures:
            print(f"domain-context-check: {failure}", file=sys.stderr)
        return 1
    ownership = parse_adr_ownership(ADR.read_text(encoding="utf-8"))
    print(
        "domain-context-check: validated "
        f"{sum(len(names) for names in ownership.values())} owned models across "
        f"{len(ownership)} contexts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
