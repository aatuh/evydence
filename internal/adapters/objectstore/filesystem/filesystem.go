package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
		if errors.Is(err, os.ErrNotExist) {
			return app.Object{}, app.ErrNotFound
		}
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

// ListObjectInventory returns a bounded page of tenant-prefixed object
// metadata without reading payload bytes. It deliberately does not offer
// deletion, and callers must treat an omitted object as an inventory gap—not
// proof that a database-owned object is missing.
func (s *Store) ListObjectInventory(ctx context.Context, tenantID string, cursor, limit int) (app.ObjectInventoryPage, error) {
	tenantID = strings.TrimSpace(tenantID)
	if s == nil || s.root == "" || !validInventoryTenantID(tenantID) || cursor < 0 || limit < 1 || limit > 10_000 {
		return app.ObjectInventoryPage{}, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return app.ObjectInventoryPage{}, err
	}
	prefix := "tenants/" + tenantID + "/"
	root, err := s.safePath(strings.TrimSuffix(prefix, "/"))
	if err != nil {
		return app.ObjectInventoryPage{}, err
	}
	page := app.ObjectInventoryPage{Objects: make([]app.ObjectInventoryItem, 0, limit)}
	matched := 0
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) && path == root {
				return filepath.SkipDir
			}
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if !strings.HasPrefix(key, prefix) || filesystemMetadataSidecar(path, key) {
			return nil
		}
		if matched < cursor {
			matched++
			return nil
		}
		if len(page.Objects) == limit {
			page.NextCursor = cursor + limit
			return filepath.SkipAll
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		page.Objects = append(page.Objects, app.ObjectInventoryItem{
			TenantID:  tenantID,
			Key:       key,
			Size:      info.Size(),
			CreatedAt: info.ModTime().UTC(),
		})
		matched++
		return nil
	})
	if walkErr != nil {
		return app.ObjectInventoryPage{}, fmt.Errorf("list filesystem object inventory: %w", walkErr)
	}
	return page, nil
}

// StagePayload streams bytes into an isolated tenant staging key while
// independently calculating the digest and size. The caller's digest is never
// trusted until it matches the exact staged byte stream.
func (s *Store) StagePayload(ctx context.Context, payload app.ObjectPayload, reader io.Reader) (app.ObjectPayload, error) {
	if err := ctx.Err(); err != nil {
		return app.ObjectPayload{}, err
	}
	if reader == nil || app.ValidateObjectPayloadForRepository(payload) != nil || payload.Status != app.ObjectPayloadStaged {
		return app.ObjectPayload{}, app.ErrValidation
	}
	path, err := s.safePath(payload.StagingKey)
	if err != nil {
		return app.ObjectPayload{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return app.ObjectPayload{}, fmt.Errorf("create staged object directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".stage-*")
	if err != nil {
		return app.ObjectPayload{}, fmt.Errorf("create staged object temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	hash := sha256.New()
	size, err := copyWithContext(ctx, io.MultiWriter(tmp, hash), reader)
	if err != nil {
		_ = tmp.Close()
		return app.ObjectPayload{}, fmt.Errorf("write staged object: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return app.ObjectPayload{}, fmt.Errorf("close staged object: %w", err)
	}
	actualDigest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if actualDigest != payload.Digest {
		return app.ObjectPayload{}, app.ErrValidation
	}
	if err := os.Rename(tmpName, path); err != nil {
		return app.ObjectPayload{}, fmt.Errorf("commit staged object: %w", err)
	}
	now := time.Now().UTC()
	payload.Size = size
	payload.UpdatedAt = now
	if payload.CreatedAt.IsZero() {
		payload.CreatedAt = now
	}
	if err := s.writeMetadata(path, metadata{Key: payload.StagingKey, TenantID: payload.TenantID, MediaType: payload.MediaType, Digest: payload.Digest, Size: payload.Size, CreatedAt: payload.CreatedAt}); err != nil {
		return app.ObjectPayload{}, err
	}
	return payload, nil
}

// FinalizePayload copies a verified staged object to its immutable final key.
// If a prior worker already copied it before crashing, the final copy is
// verified and returned instead of being overwritten.
func (s *Store) FinalizePayload(ctx context.Context, payload app.ObjectPayload) (app.Object, error) {
	if err := ctx.Err(); err != nil {
		return app.Object{}, err
	}
	if app.ValidateObjectPayloadForRepository(payload) != nil {
		return app.Object{}, app.ErrValidation
	}
	if existing, err := s.Get(ctx, payload.FinalKey); err == nil {
		if err := verifyPayloadObject(payload, existing, payload.FinalKey); err != nil {
			return app.Object{}, err
		}
		_ = s.remove(payload.StagingKey)
		return existing, nil
	} else if !errors.Is(err, app.ErrNotFound) {
		return app.Object{}, err
	}
	staged, err := s.Get(ctx, payload.StagingKey)
	if err != nil {
		return app.Object{}, err
	}
	if err := verifyPayloadObject(payload, staged, payload.StagingKey); err != nil {
		return app.Object{}, err
	}
	final := staged
	final.Key = payload.FinalKey
	if err := s.Put(ctx, final); err != nil {
		return app.Object{}, err
	}
	if err := s.remove(payload.StagingKey); err != nil {
		return app.Object{}, err
	}
	return s.Get(ctx, payload.FinalKey)
}

// CheckReadiness verifies that the configured object-store root is available
// for a small create-and-remove operation. It never includes the root path in
// an error intended for a public health response.
func (s *Store) CheckReadiness(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || strings.TrimSpace(s.root) == "" {
		return app.ErrValidation
	}
	info, err := os.Stat(s.root)
	if err != nil {
		return fmt.Errorf("stat object store root: %w", err)
	}
	if !info.IsDir() {
		return errors.New("object store root is not a directory")
	}
	temp, err := os.CreateTemp(s.root, ".evydence-readiness-*")
	if err != nil {
		return fmt.Errorf("write object store readiness marker: %w", err)
	}
	name := temp.Name()
	if err := temp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close object store readiness marker: %w", err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove object store readiness marker: %w", err)
	}
	return nil
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

func (s *Store) writeMetadata(path string, meta metadata) error {
	body, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal object metadata: %w", err)
	}
	if err := os.WriteFile(path+".json", append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("write object metadata: %w", err)
	}
	return nil
}

func (s *Store) remove(key string) error {
	path, err := s.safePath(key)
	if err != nil {
		return err
	}
	for _, target := range []string{path, path + ".json"} {
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove staged object: %w", err)
		}
	}
	return nil
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buffer := make([]byte, 32<<10)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := src.Read(buffer)
		if read > 0 {
			count, writeErr := dst.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}

func verifyPayloadObject(payload app.ObjectPayload, object app.Object, key string) error {
	if object.Key != key || object.TenantID != payload.TenantID || object.Digest != payload.Digest || int64(len(object.Bytes)) != payload.Size {
		return app.ErrValidation
	}
	return nil
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

func validInventoryTenantID(tenantID string) bool {
	return tenantID != "" && !strings.ContainsAny(tenantID, "/\\\x00") && tenantID != "." && tenantID != ".."
}

// filesystemMetadataSidecar recognizes only sidecars generated by this store.
// A user payload whose key happens to end in .json remains visible unless its
// adjacent JSON also names it as a metadata sidecar.
func filesystemMetadataSidecar(path, key string) bool {
	if !strings.HasSuffix(key, ".json") {
		return false
	}
	info, err := os.Stat(path) // #nosec G304 -- path originates from WalkDir under Store.root.
	if err != nil || info.Size() > 64<<10 {
		return false
	}
	file, err := os.Open(path) // #nosec G304 -- path originates from WalkDir under Store.root.
	if err != nil {
		return false
	}
	defer file.Close()
	var meta metadata
	if err := json.NewDecoder(io.LimitReader(file, 64<<10)).Decode(&meta); err != nil {
		return false
	}
	return meta.Key != "" && meta.Key == strings.TrimSuffix(key, ".json")
}
