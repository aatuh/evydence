package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "hash":
		if len(args) != 2 {
			return usage()
		}
		digest, err := hashFile(args[1])
		if err != nil {
			return err
		}
		fmt.Println(digest)
		return nil
	case "verify-manifest":
		if len(args) != 4 || args[2] != "--hash" {
			return usage()
		}
		return verifyManifest(args[1], args[3])
	default:
		return usage()
	}
}

func usage() error {
	return errors.New("usage: evydence hash <file> | evydence verify-manifest <manifest.json> --hash sha256:<hex>")
}

func hashFile(path string) (string, error) {
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return "", err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified file and does not use elevated privileges.
	file, err := os.Open(cleaned)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func verifyManifest(path, expected string) error {
	expected = strings.TrimSpace(expected)
	if !strings.HasPrefix(expected, "sha256:") {
		return errors.New("expected hash must use sha256:<hex>")
	}
	cleaned, err := cleanOperatorPath(path)
	if err != nil {
		return err
	}
	// #nosec G304,G703 -- this CLI command intentionally reads a local operator-specified manifest and does not use elevated privileges.
	body, err := os.ReadFile(cleaned)
	if err != nil {
		return err
	}
	var normalized any
	if err := json.Unmarshal(body, &normalized); err != nil {
		return fmt.Errorf("manifest is not JSON: %w", err)
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canonical)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != expected {
		return fmt.Errorf("manifest hash mismatch: got %s want %s", got, expected)
	}
	fmt.Println("manifest hash verified")
	return nil
}

func cleanOperatorPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("file path is required")
	}
	if strings.Contains(path, "\x00") {
		return "", errors.New("file path contains a NUL byte")
	}
	return filepath.Clean(path), nil
}
