// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import "io"

// readKeyFile reads a key file, or a Swarm secret, which holds the same form: 32 bytes as
// base64 in 44 characters, at most one trailing newline. Any other content is a *Refusal
// with KeyFileMalformed. It is the fuzz target for that reader; it refuses until it is built.
func readKeyFile(io.Reader) ([]byte, error) { return nil, errNotBuilt }
