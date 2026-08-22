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
