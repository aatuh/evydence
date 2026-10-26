package app_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func FuzzBackupStateCommitment(f *testing.F) {
	profiles := []struct {
		kind      uint8
		version   string
		resources func() []verificationapp.BackupCommitmentResource
		header    string
	}{
		{0, verificationapp.BackupStateCommitmentProfileV1, verificationapp.BackupCommitmentProfileResourcesV1, "sha256:3ef4cc91c3263312b9bddb03f17ec18701c37bd1a7f15ffd70a726b5d8864159"},
		{1, verificationapp.BackupStateCommitmentProfileV2, verificationapp.BackupCommitmentProfileResourcesV2, "sha256:dd3b77b5896b352e386ac00c2d81e0845eaebf4ac25f621e986a77e494574c4a"},
		{2, verificationapp.BackupStateCommitmentProfileV3, verificationapp.BackupCommitmentProfileResourcesV3, "sha256:1396036ce0b4c233ae42eade4a1d5596e7f70ac80168ac22e04679870d4cc79e"},
		{3, verificationapp.BackupStateCommitmentProfileV4, verificationapp.BackupCommitmentProfileResourcesV4, "sha256:cec6c60250406b7fadb0b1bc2c9b55809cbdaf6b3314db59ba01fe79c77ca52c"},
		{4, verificationapp.BackupStateCommitmentProfile, verificationapp.BackupCommitmentProfileResources, "sha256:a23c765de43cc454317a3f4e4c1429be9d83299f89e8224e2b4bb0e1efe51335"},
	}
	for _, profile := range profiles {
		d, err := verificationapp.NewBackupStateDigesterWithProfile(profile.version, "tenant", profile.resources())
		if err != nil {
			f.Fatal(err)
		}
		hash, rows, _, err := d.Finish()
		if err != nil || rows != 0 || hash != profile.header {
			f.Fatal("frozen backup profile header vector changed", err)
		}
		for mode := uint8(0); mode < 8; mode++ {
			f.Add([]byte("synthetic backup row"), profile.kind, mode)
		}
	}
	f.Add([]byte{}, uint8(4), uint8(0))
	for _, raw := range []string{
		`{"id":"tenant","name":"synthetic","created_at":"2026-10-01T12:00:00Z"}`,
		`{"id":"tenant","name":1e3,"created_at":null}`,
		`{"id":"foreign","id":"tenant","name":[],"created_at":{}}`,
		`{"id":"tenant","name":"synthetic","created_at":null} null`,
		`{"id":"foreign","name":"synthetic","created_at":null}`,
	} {
		f.Add([]byte(raw), uint8(4), uint8(0))
	}
	f.Fuzz(func(t *testing.T, raw []byte, family, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		profile := profiles[int(family)%len(profiles)]
		resources := profile.resources()
		resourcesBefore := nativeFuzzJSON(t, resources)
		row := map[string]any{"id": "tenant", "name": base64.RawStdEncoding.EncodeToString(raw), "created_at": "2026-10-01T12:00:00Z"}
		body := []byte(nativeFuzzJSON(t, row))
		before := append([]byte(nil), body...)
		makeDigester := func() *verificationapp.BackupStateDigester {
			d, err := verificationapp.NewBackupStateDigesterWithProfile(profile.version, "tenant", resources)
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
		backupFuzzRawRow(t, raw, makeDigester)
		d := makeDigester()
		if err := d.Append("tenants", "tenant", body); err != nil {
			t.Fatal("known typed row rejected by stream parser", err)
		}
		header := nativeFuzzJSON(t, struct {
			Profile, Tenant string
			Resources       []verificationapp.BackupCommitmentResource
		}{profile.version, "tenant", resources})
		line := nativeFuzzJSON(t, struct {
			Resource string         `json:"resource"`
			Key      string         `json:"key"`
			Row      map[string]any `json:"row"`
		}{"tenants", "tenant", row})
		reference := []byte(header + "\n" + line + "\n")
		hash, count, size, err := d.Finish()
		if err != nil || hash != integrityFuzzDigest(reference) || count != 1 || size != len(reference) {
			t.Fatal("stream commitment diverged from the versioned framing", err)
		}
		if _, _, _, err := d.Finish(); !errors.Is(err, verificationapp.ErrConflict) {
			t.Fatal("finished stream produced another commitment")
		}
		if err := d.Append("tenants", "tenant", body); !errors.Is(err, verificationapp.ErrConflict) {
			t.Fatal("finished stream accepted more rows")
		}
		pretty, err := json.MarshalIndent(row, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		again := makeDigester()
		if err := again.Append("tenants", "tenant", pretty); err != nil {
			t.Fatal(err)
		}
		second, secondCount, secondSize, err := again.Finish()
		if err != nil || second != hash || secondCount != count || secondSize != size {
			t.Fatal("JSON presentation changed the canonical stream commitment")
		}
		changedRow := map[string]any{"id": row["id"], "name": "changed:" + row["name"].(string), "created_at": row["created_at"]}
		changed := makeDigester()
		if err := changed.Append("tenants", "tenant", []byte(nativeFuzzJSON(t, changedRow))); err != nil {
			t.Fatal(err)
		}
		changedHash, _, _, err := changed.Finish()
		if err != nil || changedHash == hash {
			t.Fatal("changed backup row retained its commitment")
		}
		bad := makeDigester()
		resource, key := "tenants", "tenant"
		invalid := body
		switch mode % 8 {
		case 0:
			invalid = []byte(nativeFuzzJSON(t, map[string]any{"id": "foreign", "name": row["name"], "created_at": row["created_at"]}))
		case 1:
			invalid = []byte(nativeFuzzJSON(t, map[string]any{"id": "tenant", "name": row["name"], "created_at": row["created_at"], "unknown": true}))
		case 2:
			invalid = []byte(nativeFuzzJSON(t, map[string]any{"id": "tenant", "created_at": row["created_at"]}))
		case 3:
			invalid = append(append([]byte(nil), body...), []byte(" null")...)
		case 4:
			resource = "unknown"
		case 5:
			key = ""
		case 6:
			if err := bad.Append(resource, key, body); err != nil {
				t.Fatal(err)
			}
		case 7:
			invalid = []byte(`[]`)
		}
		if err := bad.Append(resource, key, invalid); !errors.Is(err, verificationapp.ErrConflict) {
			t.Fatal("unowned, out-of-order or malformed stream row accepted")
		}
		if value, _, _, err := bad.Finish(); !errors.Is(err, verificationapp.ErrConflict) || value != "" {
			t.Fatal("failed row stream published a partial commitment")
		}
		if _, err := verificationapp.NewBackupStateDigesterWithProfile(profile.version+"-unsupported", "tenant", resources); !errors.Is(err, verificationapp.ErrValidation) {
			t.Fatal("unknown commitment profile accepted")
		}
		if nativeFuzzJSON(t, resources) != resourcesBefore || !bytes.Equal(body, before) {
			t.Fatal("commitment stream mutated its vocabulary or source bytes")
		}
	})
}

// Exercise the row decoder with arbitrary bytes as well as the typed positive
// and controlled-mutation rows above. Historical JSON number spelling and
// duplicate-member interpretation belong to the declared stream profile.
func backupFuzzRawRow(t *testing.T, raw []byte, makeDigester func() *verificationapp.BackupStateDigester) {
	t.Helper()
	before := append([]byte(nil), raw...)
	first, second := makeDigester(), makeDigester()
	one := first.Append("tenants", "tenant", raw)
	two := second.Append("tenants", "tenant", raw)
	if (one == nil) != (two == nil) || !bytes.Equal(raw, before) {
		t.Fatal("raw row parsing changed across identical immutable input")
	}
	if one != nil {
		if !errors.Is(one, verificationapp.ErrConflict) || !errors.Is(two, verificationapp.ErrConflict) {
			t.Fatal("malformed raw row lost its conflict state")
		}
		if value, _, _, err := first.Finish(); !errors.Is(err, verificationapp.ErrConflict) || value != "" {
			t.Fatal("malformed raw row published a commitment")
		}
		return
	}
	a, rowsA, sizeA, errA := first.Finish()
	b, rowsB, sizeB, errB := second.Finish()
	if errA != nil || errB != nil || a == "" || a != b || rowsA != 1 || rowsB != 1 || sizeA != sizeB {
		t.Fatal("accepted raw row produced unstable commitments")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var row map[string]any
	if err := decoder.Decode(&row); err != nil || len(row) != 3 || row["id"] != "tenant" {
		t.Fatal("accepted raw row did not have the required owner and columns")
	}
	for _, name := range []string{"id", "name", "created_at"} {
		if _, exists := row[name]; !exists {
			t.Fatal("accepted raw row omitted a required column")
		}
	}
	canonical := makeDigester()
	if err := canonical.Append("tenants", "tenant", []byte(nativeFuzzJSON(t, row))); err != nil {
		t.Fatal("accepted raw row could not reproduce its canonical projection", err)
	}
	c, rowsC, sizeC, err := canonical.Finish()
	if err != nil || c != a || rowsC != rowsA || sizeC != sizeA {
		t.Fatal("raw presentation changed the declared row commitment")
	}
}
