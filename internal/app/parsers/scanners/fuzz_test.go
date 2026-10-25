package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

func scannerFuzzLimits() Limits {
	limits := DefaultLimits(64 << 10)
	limits.MaxDepth, limits.MaxStringBytes, limits.MaxValues, limits.MaxFindings = 32, 4096, 8192, 128
	return limits
}

func scannerFuzzSeeds(f *testing.F) [][]byte {
	f.Helper()
	seeds := [][]byte{[]byte(`{"release_id":"first","\u0072elease_id":"second"}`), []byte(`{} null`)}
	rows := strings.TrimSuffix(strings.Repeat(`{"vulnerability":"CVE-2026-0001","severity":"high","fix_version":"`+strings.Repeat("<", 4000)+`"},`, 15), ",")
	escaped := []byte(`{"scanner":"generic","target_ref":"pkg:oci/x","release_id":"r","findings":[` + rows + `]}`)
	if _, err := ParseBounded(escaped, scannerFuzzLimits()); err != nil {
		f.Fatalf("positive escaping seed rejected: %v", err)
	}
	seeds = append(seeds, escaped)
	for _, name := range []string{"generic", "grype", "trivy", "osv-scanner", "dependency-track"} {
		raw, err := os.ReadFile("testdata/" + name + ".json")
		if err != nil {
			f.Fatal(err)
		}
		seeds = append(seeds, raw)
	}
	seeds = append(seeds, []byte(`{"scanner":"generic","target_ref":"pkg:oci/x","release_id":"r","findings":[{"vulnerability":"CVE-1","severity":"high"},{"vulnerability":"CVE-2","severity":"low"}]}`))
	return seeds
}

func scannerFuzzRoundTrip(t *testing.T, raw []byte) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func scannerFuzzConstrainedLimits(raw []byte) []Limits {
	limits := scannerFuzzLimits()
	return []Limits{
		func() Limits { v := limits; v.MaxBytes = int64(len(raw) - 1); return v }(),
		func() Limits { v := limits; v.MaxDepth = 1; return v }(),
		func() Limits { v := limits; v.MaxStringBytes = 1; return v }(),
		func() Limits { v := limits; v.MaxValues = 1; return v }(),
	}
}

func FuzzProbeReleaseID(f *testing.F) {
	for _, raw := range scannerFuzzSeeds(f) {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		limits := scannerFuzzLimits()
		first, err := ProbeReleaseIDBoundedReader(bytes.NewReader(raw), limits)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected scope error: %v", err)
			}
			return
		}
		again, err := ProbeReleaseIDBoundedReader(iotest.HalfReader(bytes.NewReader(raw)), limits)
		if err != nil || first != again || first == "" || strings.TrimSpace(first) != first {
			t.Fatalf("scope not stable across partial reads: %v", err)
		}
		encoded := scannerFuzzRoundTrip(t, raw)
		encodedLimits := limits
		if int64(len(encoded)) > limits.MaxBytes {
			if _, err := ProbeReleaseIDBoundedReader(bytes.NewReader(encoded), limits); !errors.Is(err, ErrInvalid) {
				t.Fatal("expanded serialization escaped the original byte budget")
			}
			encodedLimits.MaxBytes = int64(len(encoded))
		}
		roundTrip, err := ProbeReleaseIDBoundedReader(bytes.NewReader(encoded), encodedLimits)
		if err != nil || first != roundTrip {
			t.Fatalf("scope changed after JSON serialization: %v", err)
		}
		duplicate := append([]byte(`{"release_id":"untrusted",`), bytes.TrimSpace(raw)[1:]...)
		if _, err := ProbeReleaseIDBoundedReader(bytes.NewReader(duplicate), limits); !errors.Is(err, ErrInvalid) {
			t.Fatal("ambiguous scope accepted")
		}
		// A scope-only object can have depth one; inject nesting to exercise
		// the depth boundary without assuming a valid scanner report.
		deep := append([]byte(`{"x-fuzz-depth":`+strings.Repeat("[", limits.MaxDepth)+"null"+strings.Repeat("]", limits.MaxDepth)+","), bytes.TrimSpace(raw)[1:]...)
		if _, err := ProbeReleaseIDBoundedReader(bytes.NewReader(deep), limits); !errors.Is(err, ErrInvalid) {
			t.Fatal("scope depth budget ignored")
		}
		constrained := scannerFuzzConstrainedLimits(raw)
		for _, budget := range []Limits{constrained[0], constrained[2], constrained[3]} {
			if _, err := ProbeReleaseIDBoundedReader(bytes.NewReader(raw), budget); !errors.Is(err, ErrInvalid) {
				t.Fatal("scope structural budget ignored")
			}
		}
		if full, err := ParseBounded(raw, limits); err == nil && first != full.ReleaseID {
			t.Fatal("scope differs from accepted full report")
		}
	})
}
