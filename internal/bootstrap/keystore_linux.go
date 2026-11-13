// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import "os"

// storeHeaderIsOurs is false because Linux has neither of Windows' key stores.
func storeHeaderIsOurs([]byte) bool {
	return false
}

// takeKey reads the key file, the only key holder the header check lets through on Linux.
func takeKey(root *os.Root, _, buffer []byte) ([]byte, error) {
	return readKeyFile(root, buffer)
}
