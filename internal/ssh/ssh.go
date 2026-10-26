// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package ssh

import (
	cryptossh "golang.org/x/crypto/ssh"
)

// The contract's operations hand their work to the unexported functions in this package, so the
// contract builds before the package is built and the build never needs to change the contract.

type hostKeyState struct {
	signer cryptossh.Signer
}
