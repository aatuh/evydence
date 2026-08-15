package app

import (
	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
	spdxparser "github.com/aatuh/evydence/internal/app/parsers/spdx"
	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
)

const (
	ParserVersionCycloneDXJSON            = cyclonedxparser.ParserVersion
	ParserVersionSPDXJSON                 = spdxparser.ParserVersion
	ParserVersionCycloneDXVEXJSON         = vexparser.CycloneDXParserVersion
	ParserVersionGenericVulnerabilityJSON = "generic-vulnerability-scan-json.v1.0.0"
	ParserVersionOpenAPIJSON              = "openapi-json.v1.0.0"
	ParserVersionOpenVEXJSON              = vexparser.OpenVEXParserVersion
	ParserVersionDSSEInTotoJSON           = "dsse-in-toto-json.v1.0.0"
)
