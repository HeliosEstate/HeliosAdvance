// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import "os"

// The seam the approved tests for issue #149 call, declared by its QA session, its body
// refusing until the build fills it. The locked tests pin its signature; the body is the
// build's.

// writeFile is the write path that create and save share, given the bootstrap folder's root,
// the bootstrap key and a whole sealed bootstrap file: it writes the file as bootstrap.hadv.new,
// truncating a leftover; flushes it; opens it under the key by the same reading open uses;
// renames it over bootstrap.hadv; and on Linux flushes the folder. If any step fails, it deletes
// bootstrap.hadv.new and returns ErrWrite.
func writeFile(*os.Root, Key256, []byte) error {
	return Error{Code: errNotBuilt}
}

// Only the Linux rows call the write path until create does; this keeps it in use on Windows.
var _ = writeFile
