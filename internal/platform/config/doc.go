// Package config defines bounded, secret-safe process configuration inputs.
// Typed settings and local/HTTP/signing/S3/database-syntax/Sigstore validation do
// not validate a complete runtime. Native database resolution, complete SDK
// coverage and command adoption remain subsequent EVY-1205 work. Typed
// construction stays private until validation is complete.
package config
