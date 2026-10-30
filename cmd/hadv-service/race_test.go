// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

//go:build race

package main_test

// raceBuild is whether the tests run under the race detector: the program is built with it then,
// and no row judges an upper bound on time, since the detector slows the engine by an amount
// nobody controls.
const raceBuild = true
