package app

import (
	"context"
)

type nopOutbox struct{}

func (nopOutbox) Enqueue(context.Context, OutboxJob) error { return nil }
