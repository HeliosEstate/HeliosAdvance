// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"encoding/binary"
	"os"
)

// storeHeaderIsOurs accepts systemd's credential and the Swarm secret, which are not key stores
// but are, with the key file, the other places a key comes from on Linux; neither has a sealed
// key in the file.
func storeHeaderIsOurs(sealed []byte) bool {
	holder := sealed[10]
	sealedKeyBytes := binary.BigEndian.Uint16(sealed[11:13])
	return (holder == KeyHolderSystemd || holder == KeyHolderSwarm) && sealedKeyBytes == 0
}

// takeKey reads the key from the place the key holder names, and from no other.
func takeKey(root *os.Root, sealed, buffer []byte) ([]byte, error) {
	switch sealed[10] {
	case KeyHolderKeyFile:
		return readKeyFile(root, buffer)
	case KeyHolderSystemd:
		return readCredential(buffer)
	default:
		return readSecret(buffer)
	}
}
