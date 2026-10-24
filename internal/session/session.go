// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// The contract's operations hand their work to the unexported functions below, so the contract
// builds before the package is built and the build never needs to change the contract.

func run(ctx context.Context, connection Connection) (Ending, error) {
	if connection == nil {
		return 0, ErrConnectionFailed
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrCallEnded, err)
	}
	// One SendString, so that the greeting and the prompt leave in one write.
	if err := connection.SendString(ctx, Greeting+Prompt); err != nil {
		return 0, ending(err)
	}
	deadline := time.Now().Add(NameSeconds * time.Second)
	name, err := connection.RecvString(ctx, deadline, NameMostCharacters)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return NoName, nil
		}
		return 0, ending(err)
	}
	if err := connection.SendString(ctx, Reply+name+"\r\n"); err != nil {
		return 0, ending(err)
	}
	return Answered, nil
}

// ending is the one mapping from a call's error to Run's, so that no layer below is imported to
// read what the caller or the connection did.
func ending(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrCallEnded, err)
	case errors.Is(err, io.EOF):
		return ErrCallerClosed
	}
	return fmt.Errorf("%w: %w", ErrConnectionFailed, err)
}
