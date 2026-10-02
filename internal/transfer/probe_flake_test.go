// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Throwaway probe on a scratch PR, never merged: the escape/send exchange with sexyz twenty
// times under CI's race detector, logging sexyz's stderr whenever the send fails, which the
// approved row cannot do because it stops before reading it.
package transfer_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/transfer"
)

func TestProbeEscapeSendFlake(t *testing.T) {
	t.Parallel()
	for attempt := range 20 {
		t.Run(fmt.Sprint(attempt), func(t *testing.T) {
			t.Parallel()
			ours, far := t.TempDir(), t.TempDir()
			src := mustWriteRandom(t, ours, "opt.bin", 200_000, mtime)
			farEnd, wait := sexyz(t, far, "-e", "-y", "rz", "/data/")
			start := time.Now()
			err := transfer.Send(within(t), farEnd, []string{src}, transfer.Options{Escape: true})
			stderr, werr := wait()
			if err != nil {
				t.Errorf("Send after %s: %v; sexyz exit %v; sexyz stderr:\n%s", time.Since(start).Round(time.Millisecond), err, werr, stderr)
				return
			}
			if mustSum(t, filepath.Join(far, "opt.bin")) != mustSum(t, src) {
				t.Error("file differs")
			}
		})
	}
}
