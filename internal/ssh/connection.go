// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh

import (
	"context"
	"fmt"
	"time"

	"github.com/heliosestate/heliosadvance/internal/timeup"
)

// connection is what the Accept call and its Channel share about one connection: when it ended.
// It holds nothing the caller sent.
type connection struct {
	// ended is closed once the library has torn the connection down, after it has marked the end
	// of every channel's data.
	ended chan struct{}
}

func newConnection() *connection {
	return &connection{ended: make(chan struct{})}
}

func (connection *connection) hasEnded() bool {
	select {
	case <-connection.ended:
		return true
	default:
		return false
	}
}

func contextEnded(ctx context.Context) error {
	cause := timeup.Ended(ctx)
	if cause == nil {
		return nil
	}
	return fmt.Errorf("ssh: the call's context ended: %w", cause)
}

func deadlineEnded(cause error) error {
	return fmt.Errorf("%w: %w", ErrDeadlineEnded, cause)
}

// waitLimit is the timer for a wait that ends at the earlier of the deadline and the context's.
func waitLimit(ctx context.Context, deadline time.Time) (<-chan time.Time, func()) {
	limit := timeup.Limit(ctx, deadline)
	if limit.IsZero() {
		return nil, func() {}
	}
	timer := time.NewTimer(time.Until(limit))
	return timer.C, func() { timer.Stop() }
}
