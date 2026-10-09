#!/usr/bin/env python3
"""Regression tests for the SDK request-field drift checker."""

from __future__ import annotations

import pathlib
import unittest
from contextlib import redirect_stderr
from io import StringIO

import sdk_check


class SDKRequestFieldContractTests(unittest.TestCase):
    def test_reads_fields_from_connected_focused_decoder(self) -> None:
        source = '''func decodeExample(body []byte) (Input, error) {
\tvar req struct {
\t\tName string `json:"name"`
\t\tSize int `json:"size"`
\t}
\treturn Input{}, nil
}
func (s *Server) createExample(w Writer, r Request) {
\tin, err := decodeExample(body)
}
func unrelated() {
\tvar req struct {
\t\tPrivate string `json:"private"`
\t}
}
'''
        self.assertEqual(
            sdk_check.handler_request_fields(source, "createExample", "decodeExample"),
            {"name", "size"},
        )

    def test_rejects_disconnected_or_missing_decoder(self) -> None:
        source = '''func decodeExample(body []byte) (Input, error) {
\tvar req struct {
\t\tName string `json:"name"`
\t}
}
func (s *Server) createExample(w Writer, r Request) {
\tdecodeOther(body)
}
'''
        cases = (
            (source, "decodeExample", "does not call request decoder"),
            (source.replace("decodeOther(body)", "decodeMissing(body)"), "decodeMissing", "Go function missing"),
        )
        for candidate, decoder, expected_error in cases:
            error = StringIO()
            with self.subTest(decoder=decoder), redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                sdk_check.handler_request_fields(candidate, "createExample", decoder)
            self.assertEqual(raised.exception.code, 2)
            self.assertIn(expected_error, error.getvalue())

    def test_current_focused_handlers_preserve_all_schema_fields(self) -> None:
        spec = sdk_check.load_openapi()
        go_client = (sdk_check.ROOT / "sdk/go/evydence/client.go").read_text(encoding="utf-8")
        typescript_client = (sdk_check.ROOT / "sdk/typescript/client.ts").read_text(encoding="utf-8")
        self.assertEqual(sdk_check.validate_request_field_contracts(spec, go_client, typescript_client), [])

    def test_missing_focused_decoder_field_is_reported(self) -> None:
        from unittest.mock import patch

        spec = sdk_check.load_openapi()
        go_client = (sdk_check.ROOT / "sdk/go/evydence/client.go").read_text(encoding="utf-8")
        typescript_client = (sdk_check.ROOT / "sdk/typescript/client.ts").read_text(encoding="utf-8")
        contract = sdk_check.REQUEST_FIELD_CONTRACTS[0]
        source = contract.handler_file.read_text(encoding="utf-8").replace('`json:"version"`', '`json:"unexpected"`')
        with patch.object(sdk_check, "REQUEST_FIELD_CONTRACTS", (contract,)), patch.object(pathlib.Path, "read_text", return_value=source):
            failures = sdk_check.validate_request_field_contracts(spec, go_client, typescript_client)
        self.assertTrue(any("handler fields" in failure and "unexpected" in failure for failure in failures))

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
