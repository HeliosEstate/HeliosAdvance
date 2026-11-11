// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The en-us file the engine is released with, the repository's own lang folder, read through Load.
package language_test

import (
	"path/filepath"
	"testing"
)

// shippedLang is the lang folder the repository ships, from this package's folder.
var shippedLang = filepath.Join("..", "..", langFolder)

func TestShippedLanguage(t *testing.T) {
	t.Parallel()

	t.Run("The engine shall be released with `lang/en-us/en-us.toml` holding every text it shows, in English (United States).", func(t *testing.T) {
		t.Parallel()
		t.Run("the shipped lang folder, board en-us: every text the page's en-us, and nothing missing", func(t *testing.T) {
			t.Parallel()
			expectShown(t, expectLoaded(t, shippedLang, fallbackCode), enUSShown)
		})
	})
}
