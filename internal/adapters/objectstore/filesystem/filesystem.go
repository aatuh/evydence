package filesystem

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
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
	rootHandle, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("open object store root: %w", err)
	}
	if err := rootHandle.Close(); err != nil {
		return nil, fmt.Errorf("close object store root: %w", err)
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
		return app.ErrValidation
	}
	key, err := safeObjectKey(object.Key)
	if err != nil {
		return err
	}
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	name := rootName(key)
	if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return fmt.Errorf("create object directory: %w", err)
	}
	if err := writeRootFileAtomic(root, name, object.Bytes, 0o600, ".tmp-"); err != nil {
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
	if err := writeMetadata(root, name, meta); err != nil {
		return err
	}
	return nil
}

func (s *Store) Get(ctx context.Context, key string) (app.Object, error) {
	if err := ctx.Err(); err != nil {
		return app.Object{}, err
	}
	key, err := safeObjectKey(key)
	if err != nil {
		return app.Object{}, err
	}
	root, err := s.openRoot()
	if err != nil {
		return app.Object{}, err
	}
	defer root.Close()
	name := rootName(key)
	body, err := root.ReadFile(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return app.Object{}, app.ErrNotFound
		}
		return app.Object{}, fmt.Errorf("read object: %w", err)
	}
	metaBody, err := root.ReadFile(name + ".json")
	if err != nil {
		return app.Object{}, fmt.Errorf("read object metadata: %w", app.ErrValidation)
	}
	var meta metadata
	if err := json.Unmarshal(metaBody, &meta); err != nil {
		return app.Object{}, fmt.Errorf("decode object metadata: %w", app.ErrValidation)
	}
	if err := validateStoredObject(key, meta, body); err != nil {
		return app.Object{}, err
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
// metadata without trusting a host path walk. It deliberately does not offer
// deletion, and callers must treat an omitted object as an inventory gap—not
// proof that a database-owned object is missing.
func (s *Store) ListObjectInventory(ctx context.Context, tenantID string, cursor, limit int) (app.ObjectInventoryPage, error) {
	if s == nil || s.root == "" || app.ValidateObjectTenantID(tenantID) != nil || cursor < 0 || limit < 1 || limit > 10_000 {
		return app.ObjectInventoryPage{}, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return app.ObjectInventoryPage{}, err
	}
	prefix, err := app.TenantObjectPrefix(tenantID)
	if err != nil {
		return app.ObjectInventoryPage{}, err
	}
	root, err := s.openRoot()
	if err != nil {
		return app.ObjectInventoryPage{}, err
	}
	defer root.Close()
	rootFS := root.FS()
	walkRoot := strings.TrimSuffix(prefix, "/")
	page := app.ObjectInventoryPage{Objects: make([]app.ObjectInventoryItem, 0, limit)}
	matched := 0
	walkErr := fs.WalkDir(rootFS, walkRoot, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) && name == walkRoot {
				return fs.SkipDir
			}
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		key := filepath.ToSlash(name)
		if err := app.ValidateTenantObjectKey(tenantID, key); err != nil {
			return err
		}
		if filesystemMetadataSidecar(rootFS, name, key) {
			return nil
		}
		if matched < cursor {
			matched++
			return nil
		}
		if len(page.Objects) == limit {
			page.NextCursor = cursor + limit
			return fs.SkipAll
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		item := app.ObjectInventoryItem{
			TenantID:  tenantID,
			Key:       key,
			Size:      info.Size(),
			CreatedAt: info.ModTime().UTC(),
		}
		if meta, err := readMetadataFS(rootFS, name+".json"); err == nil && meta.Key == key && meta.TenantID == tenantID {
			item.Digest = meta.Digest
			item.Size = meta.Size
			item.CreatedAt = meta.CreatedAt.UTC()
		}
		page.Objects = append(page.Objects, item)
		matched++
		return nil
	})
	if walkErr != nil {
		if errors.Is(walkErr, fs.ErrNotExist) {
			return page, nil
		}
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
	key, err := safeObjectKey(payload.StagingKey)
	if err != nil {
		return app.ObjectPayload{}, err
	}
	root, err := s.openRoot()
	if err != nil {
		return app.ObjectPayload{}, err
	}
	defer root.Close()
	name := rootName(key)
	if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return app.ObjectPayload{}, fmt.Errorf("create staged object directory: %w", err)
	}
	tmp, tmpName, err := createRootTemp(root, filepath.Dir(name), ".stage-", 0o600)
	if err != nil {
		return app.ObjectPayload{}, fmt.Errorf("create staged object temp file: %w", err)
	}
	defer func() { _ = root.Remove(tmpName) }()
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
	if err := root.Rename(tmpName, name); err != nil {
		return app.ObjectPayload{}, fmt.Errorf("commit staged object: %w", err)
	}
	now := time.Now().UTC()
	payload.Size = size
	payload.UpdatedAt = now
	if payload.CreatedAt.IsZero() {
		payload.CreatedAt = now
	}
	if err := writeMetadata(root, name, metadata{Key: payload.StagingKey, TenantID: payload.TenantID, MediaType: payload.MediaType, Digest: payload.Digest, Size: payload.Size, CreatedAt: payload.CreatedAt}); err != nil {
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
// for a small rooted create-and-remove operation. It never includes the root
// path in an error intended for a public health response.
func (s *Store) CheckReadiness(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	temp, name, err := createRootTemp(root, ".", ".evydence-readiness-", 0o600)
	if err != nil {
		return fmt.Errorf("write object store readiness marker: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = root.Remove(name)
		return fmt.Errorf("close object store readiness marker: %w", err)
	}
	if err := root.Remove(name); err != nil {
		return fmt.Errorf("remove object store readiness marker: %w", err)
	}
	return nil
}

func (s *Store) openRoot() (*os.Root, error) {
	if s == nil || strings.TrimSpace(s.root) == "" {
		return nil, app.ErrValidation
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, fmt.Errorf("open object store root: %w", err)
	}
	return root, nil
}

func safeObjectKey(key string) (string, error) {
	if _, err := app.TenantIDFromObjectKey(key); err != nil {
		return "", app.ErrValidation
	}
	return key, nil
}

func rootName(key string) string {
	return filepath.FromSlash(key)
}

func writeMetadata(root *os.Root, name string, meta metadata) error {
	body, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal object metadata: %w", err)
	}
	if err := writeRootFileAtomic(root, name+".json", append(body, '\n'), 0o600, ".meta-"); err != nil {
		return fmt.Errorf("write object metadata: %w", err)
	}
	return nil
}

func (s *Store) remove(key string) error {
	key, err := safeObjectKey(key)
	if err != nil {
		return err
	}
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	name := rootName(key)
	for _, target := range []string{name, name + ".json"} {
		if err := root.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove staged object: %w", err)
		}
	}
	return nil
}

func writeRootFileAtomic(root *os.Root, name string, body []byte, perm fs.FileMode, prefix string) error {
	dir := filepath.Dir(name)
	tmp, tmpName, err := createRootTemp(root, dir, prefix, perm)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmpName) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return root.Rename(tmpName, name)
}

func createRootTemp(root *os.Root, dir, prefix string, perm fs.FileMode) (*os.File, string, error) {
	for range 10 {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := path.Join(filepath.ToSlash(dir), prefix+hex.EncodeToString(random[:]))
		name = rootName(name)
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("temporary object name collision")
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
	return app.VerifyObjectPayloadRead(payload, object, key)
}

func validateObject(object app.Object) error {
	if err := app.ValidateTenantObjectKey(object.TenantID, object.Key); err != nil {
		return app.ErrValidation
	}
	if err := app.ValidateCanonicalObjectDigest(object.Digest); err != nil {
		return app.ErrValidation
	}
	if err := app.ValidateObjectMediaType(object.MediaType); err != nil {
		return app.ErrValidation
	}
	return nil
}

func validateStoredObject(key string, meta metadata, body []byte) error {
	if meta.Key != key || meta.Size != int64(len(body)) || meta.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := app.ValidateTenantObjectKey(meta.TenantID, key); err != nil {
		return app.ErrValidation
	}
	if err := app.ValidateObjectMediaType(meta.MediaType); err != nil {
		return app.ErrValidation
	}
	if err := app.VerifyObjectDigestBytes(meta.Digest, body); err != nil {
		return app.ErrValidation
	}
	return nil
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readMetadataFS(rootFS fs.FS, name string) (metadata, error) {
	file, err := rootFS.Open(filepath.ToSlash(name))
	if err != nil {
		return metadata{}, err
	}
	defer file.Close()
	var meta metadata
	if err := json.NewDecoder(io.LimitReader(file, 64<<10)).Decode(&meta); err != nil {
		return metadata{}, err
	}
	return meta, nil
}

// filesystemMetadataSidecar recognizes only sidecars generated by this store.
// A user payload whose key happens to end in .json remains visible unless its
// adjacent JSON also names it as a metadata sidecar.
func filesystemMetadataSidecar(rootFS fs.FS, name, key string) bool {
	if !strings.HasSuffix(key, ".json") {
		return false
	}
	info, err := fs.Stat(rootFS, filepath.ToSlash(name))
	if err != nil || info.Size() > 64<<10 {
		return false
	}
	meta, err := readMetadataFS(rootFS, name)
	if err != nil {
		return false
	}
	return meta.Key != "" && meta.Key == strings.TrimSuffix(key, ".json")
}
