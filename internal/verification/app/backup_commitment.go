package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
)

type BackupCommitmentResource struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

// BackupStateDigester retains a digest, declared fields and scalar counters,
// never tenant rows. Numbers preserve their JSON spelling rather than passing
// through float64. Resources and row keys must be strictly byte-ordered.
type BackupStateDigester struct {
	tenant                        string
	resources                     map[string]map[string]bool
	previousResource, previousKey string
	hash                          hash.Hash
	rows, bytes                   int
	failed, finished              bool
}

func NewBackupStateDigester(tenant string, resources []BackupCommitmentResource) (*BackupStateDigester, error) {
	if !validSigningKeyText(tenant) || len(tenant) > 1024 || len(resources) == 0 || len(resources) > 128 {
		return nil, ErrValidation
	}
	d := &BackupStateDigester{tenant: tenant, resources: map[string]map[string]bool{}, hash: sha256.New()}
	owned := make([]BackupCommitmentResource, len(resources))
	previous := ""
	for i, r := range resources {
		if !validSigningKeyText(r.Name) || len(r.Name) > 128 || r.Name <= previous || len(r.Columns) == 0 || len(r.Columns) > 128 {
			return nil, ErrValidation
		}
		columns := map[string]bool{}
		for _, c := range r.Columns {
			if !validSigningKeyText(c) || len(c) > 128 || columns[c] {
				return nil, ErrValidation
			}
			columns[c] = true
		}
		if r.Name == "tenants" {
			if !columns["id"] {
				return nil, ErrValidation
			}
		} else if !columns["tenant_id"] {
			return nil, ErrValidation
		}
		d.resources[r.Name] = columns
		previous = r.Name
		owned[i] = BackupCommitmentResource{Name: r.Name, Columns: append([]string(nil), r.Columns...)}
	}
	header, err := json.Marshal(struct {
		Profile, Tenant string
		Resources       []BackupCommitmentResource
	}{BackupStateCommitmentProfile, tenant, owned})
	if err != nil {
		return nil, err
	}
	_, _ = d.hash.Write(header)
	_, _ = d.hash.Write([]byte{'\n'})
	d.bytes = len(header) + 1
	return d, nil
}

func (d *BackupStateDigester) Append(resource, key string, raw []byte) error {
	if d.failed || d.finished {
		return ErrConflict
	}
	fail := func() error { d.failed = true; return ErrConflict }
	columns, known := d.resources[resource]
	if !known || !validSigningKeyText(key) || len(key) > 4096 || resource < d.previousResource || resource == d.previousResource && key <= d.previousKey || d.rows >= MaxBackupStateCommitmentRows || len(raw) > MaxBackupStateCommitmentBytes-d.bytes {
		return fail()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var row map[string]any
	if decoder.Decode(&row) != nil || row == nil || len(row) != len(columns) {
		return fail()
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return fail()
	}
	for name := range row {
		if !columns[name] {
			return fail()
		}
	}
	owner := row["tenant_id"]
	if resource == "tenants" {
		owner = row["id"]
	}
	if owner != d.tenant {
		return fail()
	}
	encoded, err := json.Marshal(struct {
		Resource string         `json:"resource"`
		Key      string         `json:"key"`
		Row      map[string]any `json:"row"`
	}{resource, key, row})
	if err != nil || len(encoded)+1 > MaxBackupStateCommitmentBytes-d.bytes {
		return fail()
	}
	_, _ = d.hash.Write(encoded)
	_, _ = d.hash.Write([]byte{'\n'})
	d.bytes += len(encoded) + 1
	d.rows++
	d.previousResource, d.previousKey = resource, key
	return nil
}

func (d *BackupStateDigester) Finish() (string, int, int, error) {
	if d.failed || d.finished {
		return "", 0, 0, ErrConflict
	}
	d.finished = true
	return fmt.Sprintf("sha256:%x", d.hash.Sum(nil)), d.rows, d.bytes, nil
}
