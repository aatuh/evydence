package app

import (
	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
	scannerparser "github.com/aatuh/evydence/internal/app/parsers/scanners"
	spdxparser "github.com/aatuh/evydence/internal/app/parsers/spdx"
	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
)

const (
	ParserVersionCycloneDXJSON            = cyclonedxparser.ParserVersion
	ParserVersionSPDXJSON                 = spdxparser.ParserVersion
	ParserVersionCycloneDXVEXJSON         = vexparser.CycloneDXParserVersion
	ParserVersionGenericVulnerabilityJSON = "generic-vulnerability-scan-json.v1.0.0" // retained for queued pre-EVY-505 jobs.
	ParserVersionScannerAdaptersJSON      = scannerparser.ParserVersion
	ParserVersionOpenAPIJSON              = "openapi-json.v1.0.0"
	ParserVersionOpenVEXJSON              = vexparser.OpenVEXParserVersion
	ParserVersionDSSEInTotoJSON           = "dsse-in-toto-json.v1.0.0"
)
