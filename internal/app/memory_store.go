package app

import (
	"context"
	"sync"
)

type MemoryStore struct {
	mu    sync.Mutex
	state PersistedState
	ok    bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (s *MemoryStore) LoadState(ctx context.Context) (PersistedState, bool, error) {
	if err := ctx.Err(); err != nil {
		return PersistedState{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state), s.ok, nil
}

func (s *MemoryStore) SaveState(ctx context.Context, state PersistedState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = cloneState(state)
	s.ok = true
	return nil
}
