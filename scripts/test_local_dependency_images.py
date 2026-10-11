#!/usr/bin/env python3
"""Protect the source-built local S3 fixtures and their CI wiring."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "deploy/local-dependencies/Dockerfile"
MINIO_VERSION = "v0.0.0-20251015172955-9e49d5e7a648"
MC_VERSION = "v0.0.0-20250813083541-7394ce0dd2a8"
MINIO_IMAGE = "evydence-local-minio:20251015-9e49d5e7a648"
MC_IMAGE = "evydence-local-mc:20250813-7394ce0dd2a8"


class LocalDependencyImageTests(unittest.TestCase):
    def assertContains(self, needle, source):
        self.assertTrue(needle in source, f"missing required contract: {needle}")

    def test_build_uses_verified_modules_and_immutable_base_images(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        external = [line for line in source.splitlines()
                    if line.startswith("FROM ") and ":" in line]
        self.assertEqual(len(external), 3)
        for line in external:
            self.assertRegex(line, r"@sha256:[a-f0-9]{64} AS [a-z-]+$")
        version = re.search(r"^go (\S+)$", (ROOT / "go.mod").read_text(), re.M)[1]
        self.assertContains(f"FROM golang:{version}-alpine3.23@sha256:", source)
        self.assertIn("GOTOOLCHAIN=local", source)
        self.assertIn("GOSUMDB=sum.golang.org", source)
        self.assertNotIn("GOSUMDB=off", source)
        self.assertNotIn("GONOSUMDB", source)
        self.assertContains(f"github.com/minio/minio@{MINIO_VERSION}", source)
        self.assertContains(f"github.com/minio/mc@{MC_VERSION}", source)
        self.assertNotIn("@latest", source)
        self.assertNotIn("COPY .", source, "fixtures must not copy repository secrets")

    def test_application_and_fixtures_use_the_same_verified_base_pins(self):
        source = DOCKERFILE.read_text()
        application = (ROOT / "Dockerfile").read_text()
        for prefix in ("golang:", "alpine:"):
            fixture = re.search(rf"^FROM ({prefix}[^ ]+) AS", source, re.M)[1]
            self.assertContains(f"FROM {fixture}", application)

    def test_fixture_build_context_excludes_unrelated_files(self):
        self.assertEqual((DOCKERFILE.parent / ".dockerignore").read_text().splitlines(),
                         ["*", "!Dockerfile"])

    def test_make_builds_both_exact_local_images_and_runs_this_regression(self):
        source = (ROOT / "Makefile").read_text()
        self.assertContains(f"--target minio --tag {MINIO_IMAGE}", source)
        self.assertContains(f"--target mc --tag {MC_IMAGE}", source)
        self.assertContains("local-dependency-images: local-minio-image local-mc-image", source)
        deployment = source.split("\ndeploy-check:", 1)[1].split("\nsdk-check:", 1)[0]
        self.assertIn("python3 scripts/test_local_dependency_images.py", deployment)

    def test_ci_builds_the_fixture_before_start_and_keeps_full_gates(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertLess(source.index("make local-minio-image"), source.index("docker run --detach"))
        self.assertIn(MINIO_IMAGE, source)
        self.assertNotIn("minio/minio@", source)
        self.assertIn("--publish 127.0.0.1:9000:9000", source)
        self.assertIn("run: make production-check", source)
        self.assertIn("run: make openapi-breaking-check", source)
        self.assertIn("if: always()", source)

    def test_compatibility_gate_precedes_expensive_tool_and_fixture_builds(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        compatibility = source.index("Enforce OpenAPI compatibility and deprecation policy")
        self.assertLess(compatibility, source.index("Install Go QA tools"))
        self.assertLess(compatibility, source.index("Start isolated MinIO integration service"))

    def test_compose_builds_instead_of_pulling_private_minio_images(self):
        for name in ("docker-compose.yml", "compose.production-like.yml"):
            source = (ROOT / name).read_text()
            with self.subTest(name=name):
                self.assertIn(f"image: {MINIO_IMAGE}", source)
                self.assertIn("context: ./deploy/local-dependencies", source)
                self.assertIn("target: minio", source)
                self.assertIn("pull_policy: build", source)
                self.assertNotIn("image: minio/minio", source)
                self.assertNotIn("image: minio/mc", source)
                self.assertIn("minio-data:/data", source)
                self.assertContains('"127.0.0.1:', source)
                ports = re.findall(r'^\s+- "([^"\n]+):900[01]"$', source, re.M)
                self.assertEqual(len(ports), 2)
                self.assertTrue(all(port.startswith("127.0.0.1:") for port in ports),
                                "archived fixtures must not listen on external host interfaces")
        rehearsal = (ROOT / "compose.production-like.yml").read_text()
        self.assertIn(f"image: {MC_IMAGE}", rehearsal)
        self.assertIn("target: mc", rehearsal)
        self.assertIn('mc mb --ignore-existing', rehearsal)


if __name__ == "__main__":
    unittest.main()
