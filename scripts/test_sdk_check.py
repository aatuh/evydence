#!/usr/bin/env python3
"""Regression tests for the SDK request-field drift checker."""

from __future__ import annotations

import pathlib
import unittest

import sdk_check


class SDKRequestFieldContractTests(unittest.TestCase):
    def test_parses_required_and_optional_sdk_fields(self) -> None:
        go_fields, go_required = sdk_check.go_request_fields(
            'type ExampleRequest struct {\nName string `json:"name"`\nSize int `json:"size,omitempty"`\n}\n',
            "ExampleRequest",
        )
        typescript_fields, typescript_required = sdk_check.typescript_request_fields(
            "export type ExampleRequest = {\n  name: string;\n  size?: number;\n};\n",
            "ExampleRequest",
        )

        self.assertEqual(go_fields, {"name", "size"})
        self.assertEqual(go_required, {"name"})
        self.assertEqual(typescript_fields, {"name", "size"})
        self.assertEqual(typescript_required, {"name"})

    def test_reports_field_drift(self) -> None:
        previous_contracts = sdk_check.REQUEST_FIELD_CONTRACTS
        previous_handler_fields = sdk_check.handler_request_fields
        try:
            sdk_check.REQUEST_FIELD_CONTRACTS = (
                sdk_check.RequestFieldContract(
                    "example",
                    "ExampleRequest",
                    "ExampleRequest",
                    "ExampleRequest",
                    pathlib.Path(__file__),
                    "unused",
                ),
            )
            sdk_check.handler_request_fields = lambda _source, _name: {"name"}  # type: ignore[method-assign]
            failures = sdk_check.validate_request_field_contracts(
                {"components": {"schemas": {"ExampleRequest": {"properties": {"name": {}, "size": {}}, "required": ["name"]}}}},
                'type ExampleRequest struct {\nName string `json:"name"`\nSize int `json:"size,omitempty"`\n}\n',
                "export type ExampleRequest = {\n  name: string;\n};\n",
            )
        finally:
            sdk_check.REQUEST_FIELD_CONTRACTS = previous_contracts
            sdk_check.handler_request_fields = previous_handler_fields

        self.assertTrue(any("TypeScript SDK fields" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
