// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package language

import "errors"

// The contract's operations hand their work to the unexported functions in this package's other
// files, so the contract builds before the package is built and the build never needs to change
// the contract. Until Languages Part 1's build, every call fails.

var errNotBuilt = errors.New("language: not built yet")

type texts struct{}

func load(string, string) (*Texts, error) {
	return nil, errNotBuilt
}

func (*texts) text(string, []Value) string {
	return ""
}

func (*texts) missing() []string {
	return nil
}
