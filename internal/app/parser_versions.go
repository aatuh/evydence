package app

import cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"

const (
	ParserVersionCycloneDXJSON            = cyclonedxparser.ParserVersion
	ParserVersionCycloneDXVEXJSON         = "cyclonedx-vex-json.v1.0.0"
	ParserVersionGenericVulnerabilityJSON = "generic-vulnerability-scan-json.v1.0.0"
	ParserVersionOpenAPIJSON              = "openapi-json.v1.0.0"
	ParserVersionOpenVEXJSON              = "openvex-json.v1.0.0"
	ParserVersionDSSEInTotoJSON           = "dsse-in-toto-json.v1.0.0"
)
