// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package main

import "os"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "x" {
		os.Exit(2)
	}
}
