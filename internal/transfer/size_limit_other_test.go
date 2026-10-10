// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package transfer_test

import "os"

// markSparse has nothing to do here: a file extended by its length alone is already sparse
// on the file systems the rows run on outside Windows.
func markSparse(*os.File) error {
	return nil
}
