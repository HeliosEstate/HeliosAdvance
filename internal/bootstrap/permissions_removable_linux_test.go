// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRemovableAt proves the Removable rule reaches a removable disk under a stack of devices:
// a device-mapper device has no flag of its own, so its slaves/ are walked.
func TestRemovableAt(t *testing.T) {
	flagOf := func(removable string) func(t *testing.T, root string) {
		return func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, "disk", "removable"), []byte(removable+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	rows := []struct {
		name   string
		layout func(t *testing.T, root string) string // builds the sysfs tree, returns the device directory to judge
		want   bool
	}{
		{"a removable disk", func(t *testing.T, root string) string { flagOf("1")(t, root); return filepath.Join(root, "disk") }, true},
		{"a fixed disk", func(t *testing.T, root string) string { flagOf("0")(t, root); return filepath.Join(root, "disk") }, false},
		{"a partition takes its disk's flag", func(t *testing.T, root string) string {
			flagOf("1")(t, root)
			mustMkdir(t, filepath.Join(root, "disk", "part"))
			return filepath.Join(root, "disk", "part")
		}, true},
		{"a device-mapper device over a removable disk", func(t *testing.T, root string) string {
			flagOf("1")(t, root)
			mustMkdir(t, filepath.Join(root, "dm", "slaves"))
			if err := os.Symlink(filepath.Join(root, "disk"), filepath.Join(root, "dm", "slaves", "sda")); err != nil {
				t.Skip("no symbolic links here:", err)
			}
			return filepath.Join(root, "dm")
		}, true},
		{"a device-mapper device over a fixed disk", func(t *testing.T, root string) string {
			flagOf("0")(t, root)
			mustMkdir(t, filepath.Join(root, "dm", "slaves"))
			if err := os.Symlink(filepath.Join(root, "disk"), filepath.Join(root, "dm", "slaves", "sda")); err != nil {
				t.Skip("no symbolic links here:", err)
			}
			return filepath.Join(root, "dm")
		}, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			mustMkdir(t, filepath.Join(root, "disk"))
			device := row.layout(t, root)
			if got := removableAt(device, maxStackDepth); got != row.want {
				t.Errorf("removableAt = %v, want %v", got, row.want)
			}
		})
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}
