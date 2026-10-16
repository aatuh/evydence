#!/usr/bin/env python3
"""Render deployment contracts without starting containers or contacting a cluster."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/evydence"


class DeploymentLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helm = os.environ.get("HELM_BIN", "helm")
        if not shutil.which(cls.helm):
            raise RuntimeError("Helm is required for deployment lifecycle checks; set HELM_BIN if needed")
        subprocess.run(["docker", "compose", "version"], check=True, capture_output=True, text=True)

    def render(self, overrides=None, image=True):
        with tempfile.TemporaryDirectory(prefix="evydence-helm-lifecycle-") as directory:
            values = Path(directory) / "values.json"
            values.write_text(json.dumps(overrides or {}))
            command = [self.helm, "template", "lifecycle", str(CHART), "--values", str(values)]
            if image:
                command += ["--set", "image.tag=lifecycle-fixture"]
            return subprocess.run(command, check=False, capture_output=True, text=True, timeout=20)

    def manifests(self, overrides=None):
        result = self.render(overrides)
        self.assertEqual(result.returncode, 0, result.stderr)
        documents = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
        config = next(doc["data"] for doc in documents if doc["kind"] == "ConfigMap")
        deployments = {
            doc["spec"]["template"]["metadata"]["labels"]["app.kubernetes.io/component"]: doc
            for doc in documents if doc["kind"] == "Deployment"
        }
        self.assertEqual(set(deployments), {"api", "worker"})
        self.assertEqual(deployments["api"]["spec"]["replicas"], 1)
        self.assertEqual(deployments["api"]["spec"]["strategy"], {"type": "Recreate"})
        self.assertEqual(config["EVYDENCE_API_WRITER_MODE"], "single")
        self.assertEqual(config["EVYDENCE_API_WRITER_REPLICAS"], "1")
        cleanup = int(config["EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS"])
        for component, variable in [("api", "EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS"),
                                    ("worker", "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS")]:
            pod = deployments[component]["spec"]["template"]["spec"]
            self.assertGreaterEqual(pod["terminationGracePeriodSeconds"], int(config[variable]) + cleanup + 5)
        return config, deployments

    def test_defaults_cover_both_daemon_budgets_and_safe_writer_rollout(self):
        config, deployments = self.manifests()
        self.assertEqual(config["EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS"], "5")
        self.assertEqual(config["EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS"], "30")
        for deployment in deployments.values():
            self.assertEqual(deployment["spec"]["template"]["spec"]["terminationGracePeriodSeconds"], 40)

    def test_api_probes_use_distinct_lifecycle_routes_and_bounded_budgets(self):
        _, deployments = self.manifests()
        api = deployments["api"]["spec"]["template"]["spec"]["containers"][0]
        for kind, path in [("startup", "/v1/startup"), ("readiness", "/v1/ready"), ("liveness", "/v1/health")]:
            probe = api[kind + "Probe"]
            self.assertEqual(probe["httpGet"], {"path": path, "port": "http"})
            self.assertGreaterEqual(probe["periodSeconds"], 5)
            self.assertGreaterEqual(probe["failureThreshold"], 3)
            self.assertEqual(probe["successThreshold"], 1)
            if kind != "liveness":
                self.assertGreater(probe["timeoutSeconds"], 3, "allow the full dependency-refresh budget")
            else:
                self.assertEqual(probe["timeoutSeconds"], 2)
        startup = api["startupProbe"]
        self.assertGreaterEqual(startup["failureThreshold"] * startup["periodSeconds"], 300)

    def test_worker_probes_query_live_daemon_with_distinct_modes(self):
        config, deployments = self.manifests()
        self.assertEqual(config["EVYDENCE_WORKER_HEALTH_ADDR"], "127.0.0.1:8081")
        worker = deployments["worker"]["spec"]["template"]["spec"]["containers"][0]
        for kind, mode in [("startup", ["--startup"]), ("readiness", []), ("liveness", ["--liveness"])]:
            probe = worker[kind + "Probe"]
            self.assertEqual(probe["exec"]["command"], ["evydence-worker", "healthcheck", *mode])
            self.assertGreaterEqual(probe["periodSeconds"], 5)
            self.assertGreaterEqual(probe["failureThreshold"], 3)
            self.assertEqual(probe["successThreshold"], 1)
            self.assertEqual(probe["timeoutSeconds"], 2 if kind == "liveness" else 6)
        startup = worker["startupProbe"]
        self.assertGreaterEqual(startup["failureThreshold"] * startup["periodSeconds"], 300)
        custom, deployments = self.manifests({"worker": {"healthPort": 18081, "probes": {"enabled": False}}})
        self.assertEqual(custom["EVYDENCE_WORKER_HEALTH_ADDR"], "127.0.0.1:18081")
        worker = deployments["worker"]["spec"]["template"]["spec"]["containers"][0]
        for kind in ("startup", "readiness", "liveness"):
            self.assertNotIn(kind + "Probe", worker)
        for invalid in (0, 65536, "8081", True, 8081.5):
            self.assertNotEqual(self.render({"worker": {"healthPort": invalid}}).returncode, 0)

    def test_runtime_credentials_use_selected_secret_without_overriding_chart_safety(self):
        for overrides, selected in [({}, {"api": "evydence-secrets", "worker": "evydence-secrets"}),
                                    ({"api": {"existingSecret": "api-runtime"}, "worker": {"existingSecret": "worker-runtime"}},
                                     {"api": "api-runtime", "worker": "worker-runtime"})]:
            _, deployments = self.manifests(overrides)
            for component in ("api", "worker"):
                container = deployments[component]["spec"]["template"]["spec"]["containers"][0]
                self.assertEqual(container["envFrom"][0], {"secretRef": {"name": selected[component]}})
                self.assertIn("configMapRef", container["envFrom"][-1], "chart safety settings must take precedence")
                for name in ("EVYDENCE_DATABASE_URL", "EVYDENCE_API_KEY_PEPPER"):
                    variable = next(value for value in container["env"] if value["name"] == name)
                    self.assertEqual(variable["valueFrom"]["secretKeyRef"]["name"], selected[component])

    def test_config_revision_is_projected_and_rolls_all_configuration_consumers(self):
        config, deployments = self.manifests()
        revision = config["EVYDENCE_CONFIGURATION_REVISION"]
        self.assertRegex(revision, r"^[0-9a-f]{64}$")
        annotations = []
        for component in ("api", "worker"):
            annotations.append(deployments[component]["spec"]["template"]["metadata"]["annotations"]["checksum/config"])
        self.assertEqual(annotations[0], annotations[1])
        for component in ("api", "worker"):
            pod = deployments[component]["spec"]["template"]["spec"]
            container = pod["containers"][0]
            path = next(value["value"] for value in container["env"] if value["name"] == "EVYDENCE_CONFIGURATION_REVISION_FILE")
            mount = next(value for value in container["volumeMounts"] if value["name"] == "configuration-revision")
            self.assertTrue(mount["readOnly"])
            self.assertNotIn("subPath", mount, "subPath mounts do not observe ConfigMap projection updates")
            volume = next(value for value in pod["volumes"] if value["name"] == mount["name"])
            self.assertEqual(volume["configMap"]["items"], [{"key": "EVYDENCE_CONFIGURATION_REVISION", "path": "revision"}])
            self.assertEqual(path, mount["mountPath"] + "/revision")
        changed, replacement = self.manifests({"api": {"maxInFlightRequests": 512}})
        self.assertNotEqual(changed["EVYDENCE_CONFIGURATION_REVISION"], revision)
        for component, previous in zip(("api", "worker"), annotations):
            self.assertNotEqual(replacement[component]["spec"]["template"]["metadata"]["annotations"]["checksum/config"], previous)

    def test_custom_budgets_and_worker_scaling_render(self):
        config, deployments = self.manifests({"cleanupTimeoutSeconds": 60,
            "api": {"shutdownTimeoutSeconds": 300, "terminationGracePeriodSeconds": 365},
            "worker": {"shutdownTimeoutSeconds": 180, "terminationGracePeriodSeconds": 245, "replicas": 3}})
        self.assertEqual(config["EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS"], "300")
        self.assertEqual(config["EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS"], "180")
        self.assertEqual(deployments["worker"]["spec"]["replicas"], 3)
        self.manifests({"cleanupTimeoutSeconds": 1,
            "api": {"shutdownTimeoutSeconds": 1, "terminationGracePeriodSeconds": 7},
            "worker": {"shutdownTimeoutSeconds": 1, "terminationGracePeriodSeconds": 7}})

    def test_undersized_grace_is_rejected_for_each_daemon(self):
        for component in ("api", "worker"):
            with self.subTest(component=component):
                result = self.render({component: {"terminationGracePeriodSeconds": 39}})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("terminationGracePeriodSeconds", result.stderr)
        result = self.render({"cleanupTimeoutSeconds": 60,
            "api": {"shutdownTimeoutSeconds": 300, "terminationGracePeriodSeconds": 364}})
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_types_and_runtime_ranges_fail_rendering(self):
        for path, invalid in [("api", 0), ("api", 301), ("worker", 0), ("worker", 301),
                              ("api", "30"), ("worker", True), ("api", 1.5)]:
            with self.subTest(path=path, value=invalid):
                result = self.render({path: {"shutdownTimeoutSeconds": invalid}})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("shutdownTimeoutSeconds", result.stderr)
        for invalid in (0, 61, "5", True, 1.5):
            with self.subTest(cleanup=invalid):
                result = self.render({"cleanupTimeoutSeconds": invalid})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("cleanupTimeoutSeconds", result.stderr)

    def test_second_api_writer_and_missing_image_tag_stay_rejected(self):
        result = self.render({"api": {"replicas": 2}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("replicas", result.stderr)
        result = self.render(image=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image.tag", result.stderr)

    def test_grace_types_and_bounds_are_not_coerced(self):
        for component in ("api", "worker"):
            for invalid in ("40", 40.5, True, 0, -1, 3601):
                with self.subTest(component=component, value=invalid):
                    result = self.render({component: {"terminationGracePeriodSeconds": invalid}})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("terminationGracePeriodSeconds", result.stderr)

    def test_compose_grace_covers_default_and_maximum_supported_budgets(self):
        for maximum in (False, True):
            with self.subTest(maximum=maximum):
                env = {key: value for key, value in os.environ.items()
                       if not key.startswith(("EVYDENCE_", "MINIO_", "POSTGRES_"))}
                env.update({"POSTGRES_PASSWORD": "fixture-only", "MINIO_ROOT_PASSWORD": "fixture-only",
                            "EVYDENCE_API_KEY_PEPPER": "fixture-only",
                            "EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS": "300" if maximum else "30",
                            "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS": "300" if maximum else "30",
                            "EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS": "60" if maximum else "5"})
                result = subprocess.run(["docker", "compose", "--env-file", os.devnull, "-f",
                    str(ROOT / "compose.production-like.yml"), "config", "--format", "json"],
                    env=env, check=True, capture_output=True, text=True, timeout=20)
                services = json.loads(result.stdout)["services"]
                for component, variable in [("api", "EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS"),
                                            ("worker", "EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS")]:
                    service = services[component]
                    values = service["environment"]
                    self.assertEqual(service["stop_signal"], "SIGTERM")
                    duration = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", service["stop_grace_period"])
                    self.assertIsNotNone(duration, "unsupported Compose duration encoding")
                    seconds = sum(int(value or 0) * factor for value, factor in zip(duration.groups(), (3600, 60, 1)))
                    self.assertGreaterEqual(seconds, int(values[variable]) + int(values["EVYDENCE_SHUTDOWN_CLEANUP_TIMEOUT_SECONDS"]) + 5)


if __name__ == "__main__":
    unittest.main()
