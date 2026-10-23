#!/usr/bin/env python3
"""Regression tests for the generated public API inventory."""

from __future__ import annotations

import unittest

import api_inventory


def operation(**overrides: object) -> dict:
    value = {
        "operationId": "listProducts",
        "x-evydence-stability": "core",
        "x-scopes": ["product:read"],
        "security": [{"BearerAuth": []}],
        "responses": {
            "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProductListEnvelope"}}}},
            "400": {"content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}},
        },
    }
    value.update(overrides)
    return value


class APIInventoryTests(unittest.TestCase):
    def test_startup_is_public_platform_health_without_exempting_similar_paths(self) -> None:
        startup = operation(operationId="startup", security=[], **{"x-scopes": [], "x-evydence-stability": "supported"})
        spec = {"paths": {"/v1/startup": {"get": startup}}}
        self.assertEqual(api_inventory.validate_spec(spec), [])
        entry = api_inventory.inventory_from_spec(spec)["operations"][0]
        self.assertEqual(entry["owner"], "platform-operations")
        self.assertEqual(entry["auth"], "public")
        for path in ("/v1/startup-extra", "/v1/startup/private"):
            failures = api_inventory.validate_spec({"paths": {path: {"get": startup}}})
            self.assertTrue(any("auth/scopes contract" in failure for failure in failures))

    def test_saml_state_is_public_without_exempting_other_sso_routes(self) -> None:
        public = operation(operationId="beginSAMLAuthentication", security=[], **{"x-scopes": []})
        spec = {"paths": {"/v1/sso/saml-authentication-requests": {"post": public}}}
        self.assertEqual(api_inventory.validate_spec(spec), [])
        self.assertEqual(api_inventory.inventory_from_spec(spec)["operations"][0]["auth"], "public-login-state")
        for path in ("/v1/sso/providers/provider/saml-binding", "/v1/sso/unknown"):
            failures = api_inventory.validate_spec({"paths": {path: {"post": public}}})
            self.assertTrue(any("auth/scopes contract" in failure for failure in failures))

    def test_inventory_includes_contract_fields(self) -> None:
        spec = {"paths": {"/v1/products": {"get": operation()}}}

        inventory = api_inventory.inventory_from_spec(spec)

        self.assertEqual(inventory["operation_count"], 1)
        entry = inventory["operations"][0]
        self.assertEqual(entry["operation_id"], "listProducts")
        self.assertEqual(entry["owner"], "release-ledger")
        self.assertEqual(entry["auth"], "bearer")
        self.assertEqual(entry["error_statuses"], ["400"])
        self.assertEqual(entry["response_schemas"], {"200": ["ProductListEnvelope"], "400": ["Problem"]})

    def test_explicit_operation_owner_overrides_path_family(self) -> None:
        spec = {
            "paths": {
                "/v1/products": {
                    "get": operation(**{"x-evydence-owner": "release-catalog"})
                }
            }
        }

        entry = api_inventory.inventory_from_spec(spec)["operations"][0]

        self.assertEqual(entry["owner"], "release-catalog")

    def test_validation_reports_duplicate_and_missing_contract_fields(self) -> None:
        spec = {
            "paths": {
                "/v1/products": {"get": operation()},
                "/v1/unowned": {
                    "post": operation(
                        **{
                            "operationId": "listProducts",
                            "x-evydence-stability": "",
                            "x-scopes": [],
                            "security": [],
                            "requestBody": {"content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}}},
                            "responses": {"200": {"description": "generic"}},
                        }
                    )
                },
            }
        }

        failures = api_inventory.validate_spec(spec)

        self.assertTrue(any("duplicate operationId" in failure for failure in failures))
        self.assertTrue(any("missing stability" in failure for failure in failures))
        self.assertTrue(any("missing owner" in failure for failure in failures))
        self.assertTrue(any("broad request schema" in failure for failure in failures))
        self.assertTrue(any("success response schema" in failure for failure in failures))
        self.assertTrue(any("error response" in failure for failure in failures))
        self.assertTrue(any("auth/scopes contract" in failure for failure in failures))

    def test_public_operation_can_have_explicit_public_auth_contract(self) -> None:
        spec = {
            "paths": {
                "/v1/openapi.json": {
                    "get": operation(operationId="openapi", security=[], **{"x-scopes": []})
                }
            }
        }

        self.assertEqual(api_inventory.validate_spec(spec), [])


if __name__ == "__main__":
    unittest.main()
