#!/usr/bin/env python3
"""Render fake operator inputs for tagged startup tests; never start services."""
import argparse
import base64
import json
import os

from test_deployment_lifecycle import DeploymentLifecycleTests


SECRET_VALUES = {
    "EVYDENCE_DATABASE_URL": "postgres://fixture:PRIVATE_DATABASE_PASSWORD@database.example.test:5432/evydence?sslmode=disable",
    "EVYDENCE_API_KEY_PEPPER": "PRIVATE_API_PEPPER_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "EVYDENCE_S3_ACCESS_KEY_ID": "PRIVATE_S3_ACCESS_ID",
    "EVYDENCE_S3_SECRET_ACCESS_KEY": "PRIVATE_S3_SECRET_KEY",
    "EVYDENCE_SIGNING_EXECUTOR_TOKEN": "PRIVATE_SIGNING_TOKEN",
    "EVYDENCE_PROVIDER_VALIDATION_GATEWAY_TOKEN": "PRIVATE_PROVIDER_TOKEN",
    "EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_TOKEN": "PRIVATE_TRANSPARENCY_TOKEN",
}
PROVIDER_OPTIONS = {
    "EVYDENCE_SIGNING_EXECUTOR_URL": "https://signer.example.test/sign",
    "EVYDENCE_SIGNING_EXECUTOR_READINESS_URL": "https://signer.example.test/ready",
    "EVYDENCE_SIGNING_EXECUTOR_PUBLIC_KEY_BASE64": base64.b64encode(bytes(32)).decode(),
    "EVYDENCE_SIGNING_EXECUTOR_TIMEOUT_SECONDS": "17",
    "EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL": "https://identity.example.test/validate",
    "EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL": "https://proof.example.test/proof",
}


def helm_fixture(case, process, mode):
    if process not in ("api", "worker"):
        raise ValueError("unsupported Helm process")
    values = {
        "cleanupTimeoutSeconds": 3,
        "env": {"s3Endpoint": "storage.example.test", "s3Bucket": "fixture-evidence"},
        "api": {"existingSecret": "api-credentials", "secretSource": mode, "readHeaderTimeoutSeconds": 7},
        "worker": {"existingSecret": "worker-credentials", "secretSource": mode, "pollInterval": "250ms"},
    }
    if mode == "files":
        values["podSecurityContext"] = {"fsGroup": 2000}
        values["api"].update({"environmentSecret": "api-options", "secretFiles": {
            name + "_FILE": name for name in SECRET_VALUES if name.endswith("_TOKEN")}})
    config, deployments = case.manifests(values)
    worker_secret = {name: value for name, value in SECRET_VALUES.items()
                     if name == "EVYDENCE_DATABASE_URL" or name.startswith("EVYDENCE_S3_")}
    secrets = {"api-credentials": dict(SECRET_VALUES, **PROVIDER_OPTIONS),
               "worker-credentials": worker_secret, "api-options": PROVIDER_OPTIONS}
    pod = deployments[process]["spec"]["template"]["spec"]
    container = pod["containers"][0]
    config_name = next(entry["configMapRef"]["name"] for entry in container["envFrom"] if "configMapRef" in entry)
    config_maps = {config_name: config}
    environment = {}
    for entry in container["envFrom"]:
        if "secretRef" in entry:
            environment.update(secrets[entry["secretRef"]["name"]])
        else:
            environment.update(config_maps[entry["configMapRef"]["name"]])
    for entry in container["env"]:
        if "value" in entry:
            environment[entry["name"]] = entry["value"]
        else:
            reference = entry["valueFrom"]["secretKeyRef"]
            environment[entry["name"]] = secrets[reference["name"]][reference["key"]]
    mounts = []
    for mount in container["volumeMounts"]:
        if not mount.get("readOnly") or "subPath" in mount:
            raise ValueError("fixture expects read-only directory projections")
        volume = next(entry for entry in pod["volumes"] if entry["name"] == mount["name"])
        kind = "secret" if "secret" in volume else "configMap"
        reference = volume[kind]
        data = secrets[reference["secretName"]] if kind == "secret" else config_maps[reference["name"]]
        mounts.append({"guest": mount["mountPath"], "mode": reference.get("defaultMode", 0o644),
                       "files": {item["path"]: data[item["key"]] for item in reference["items"]}})
    return {"environment": environment, "mounts": mounts,
            "expected": SECRET_VALUES if process == "api" else worker_secret}


def compose_fixture(case, process, mode):
    if process not in ("api", "worker", "migrate") or (mode == "files" and process != "migrate"):
        raise ValueError("unsupported Compose fixture selection")
    values = dict(PROVIDER_OPTIONS, POSTGRES_PASSWORD="PRIVATE_DATABASE_PASSWORD",
                  MINIO_ROOT_USER=SECRET_VALUES["EVYDENCE_S3_ACCESS_KEY_ID"],
                  MINIO_ROOT_PASSWORD=SECRET_VALUES["EVYDENCE_S3_SECRET_ACCESS_KEY"],
                  EVYDENCE_API_KEY_PEPPER=SECRET_VALUES["EVYDENCE_API_KEY_PEPPER"],
                  EVYDENCE_SIGNING_EXECUTOR_TOKEN=SECRET_VALUES["EVYDENCE_SIGNING_EXECUTOR_TOKEN"])
    service = case.compose_services(values)[process]
    expected = {name: value for name, value in service["environment"].items() if name in SECRET_VALUES}
    mounts = []
    if mode == "files":
        target = "/run/evydence/private/EVYDENCE_DATABASE_URL_FILE"
        # This is an operator override, not a profile shipped by the base stack.
        override = {"services": {"migrate": {"environment": {
            "EVYDENCE_DATABASE_URL": "", "EVYDENCE_DATABASE_URL_FILE": target},
            "group_add": ["2000"], "volumes": [{"type": "bind", "source": "/fixture/private-database-url",
                "target": target, "read_only": True, "bind": {"create_host_path": False}}]}}}
        service = case.compose_services(values, override)[process]
        bind = next(item for item in service["volumes"] if item["target"] == target)
        if not bind.get("read_only") or bind["type"] != "bind" or service["group_add"] != ["2000"]:
            raise ValueError("invalid private migration override")
        directory, filename = target.rsplit("/", 1)
        mounts.append({"guest": directory, "mode": 0o440,
                       "files": {filename: expected["EVYDENCE_DATABASE_URL"]}})
    return {"environment": service["environment"], "mounts": mounts, "expected": expected}


def operator_fixture(process, mode):
    if process != "cli":
        raise ValueError("unsupported operator fixture")
    expected = {"EVYDENCE_API_KEY": "PRIVATE_CLI_KEY", "EVYDENCE_API_URL": "https://api.example.test"}
    environment = dict(expected, ENV="production")
    mounts = []
    if mode == "files":
        del environment["EVYDENCE_API_KEY"]
        environment["EVYDENCE_API_KEY_FILE"] = "/run/evydence/cli/key"
        mounts.append({"guest": "/run/evydence/cli", "mode": 0o440,
                       "files": {"key": expected["EVYDENCE_API_KEY"]}})
    return {"environment": environment, "mounts": mounts, "expected": expected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, choices=("helm", "compose", "operator"))
    parser.add_argument("--process", required=True, choices=("api", "worker", "migrate", "cli"))
    parser.add_argument("--secret-source", required=True, choices=("env", "files"))
    args = parser.parse_args()
    case = DeploymentLifecycleTests("test_defaults_cover_both_daemon_budgets_and_safe_writer_rollout")
    case.helm = os.environ.get("HELM_BIN", "helm")
    if args.source == "helm":
        result = helm_fixture(case, args.process, args.secret_source)
    elif args.source == "compose":
        result = compose_fixture(case, args.process, args.secret_source)
    else:
        result = operator_fixture(args.process, args.secret_source)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
