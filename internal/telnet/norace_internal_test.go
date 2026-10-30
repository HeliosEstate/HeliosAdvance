// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !race

package telnet

// raceBuild is whether the tests run under the race detector, under which no upper bound on time
// is judged.
const raceBuild = false
