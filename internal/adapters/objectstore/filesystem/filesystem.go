package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

type Store struct {
	root string
}

type metadata struct {
	Key       string    `json:"key"`
	TenantID  string    `json:"tenant_id"`
	MediaType string    `json:"media_type,omitempty"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

func New(root string) (*Store, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("object store root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve object store root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create object store root: %w", err)
	}
	return &Store{root: abs}, nil
}

func (s *Store) Put(ctx context.Context, object app.Object) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateObject(object); err != nil {
		return err
	}
	if got := digestBytes(object.Bytes); got != object.Digest {
		return fmt.Errorf("object digest mismatch")
	}
	path, err := s.safePath(object.Key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create object directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("create object temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(object.Bytes); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write object temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close object temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("commit object file: %w", err)
	}
	meta := metadata{
		Key:       object.Key,
		TenantID:  object.TenantID,
		MediaType: object.MediaType,
		Digest:    object.Digest,
		Size:      int64(len(object.Bytes)),
		CreatedAt: object.CreatedAt,
	}
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	body, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal object metadata: %w", err)
	}
	if err := os.WriteFile(path+".json", append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("write object metadata: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, key string) (app.Object, error) {
	if err := ctx.Err(); err != nil {
		return app.Object{}, err
	}
	path, err := s.safePath(key)
	if err != nil {
		return app.Object{}, err
	}
	body, err := os.ReadFile(path) // #nosec G304 -- path is constrained under Store.root by safePath.
	if err != nil {
		return app.Object{}, fmt.Errorf("read object: %w", err)
	}
	var meta metadata
	if metaBody, err := os.ReadFile(path + ".json"); err == nil { // #nosec G304 -- metadata path shares the safe object path prefix.
		if err := json.Unmarshal(metaBody, &meta); err != nil {
			return app.Object{}, fmt.Errorf("decode object metadata: %w", err)
		}
	}
	return app.Object{
		Key:       key,
		TenantID:  meta.TenantID,
		MediaType: meta.MediaType,
		Digest:    meta.Digest,
		Bytes:     body,
		CreatedAt: meta.CreatedAt,
	}, nil
}

func (s *Store) safePath(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" || strings.ContainsRune(key, 0) || filepath.IsAbs(key) {
		return "", fmt.Errorf("invalid object key")
	}
	clean := filepath.Clean(filepath.FromSlash(key))
	if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", fmt.Errorf("invalid object key")
	}
	path := filepath.Join(s.root, clean)
	rel, err := filepath.Rel(s.root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid object key")
	}
	return path, nil
}

func validateObject(object app.Object) error {
	if strings.TrimSpace(object.Key) == "" || strings.TrimSpace(object.TenantID) == "" {
		return fmt.Errorf("invalid object")
	}
	if !strings.HasPrefix(object.Key, "tenants/"+object.TenantID+"/") {
		return fmt.Errorf("object key must be tenant-prefixed")
	}
	if !strings.HasPrefix(object.Digest, "sha256:") {
		return fmt.Errorf("invalid object digest")
	}
	return nil
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
