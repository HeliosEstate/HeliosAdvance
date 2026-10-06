// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRemovableAt proves the Removable rule reaches a removable disk as sysfs lays it out:
// /sys/dev/block/<major>:<minor> is a symbolic link to the device's real directory, a partition's
// directory sits inside its disk's, and a device-mapper device has a removable file of its own
// reading 0 and slaves/ entries that link to the devices it is built on.
func TestRemovableAt(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name      string
		removable string // what the disk's removable file reads
		judge     string // the device to judge: a link from block/, as the kernel gives it
		want      bool
	}{
		{"a removable disk", "1", "disk", true},
		{"a fixed disk", "0", "disk", false},
		{"a partition of a removable disk", "1", "partition", true},
		{"a partition of a fixed disk", "0", "partition", false},
		{"a device-mapper device over a removable partition", "1", "mapper", true},
		{"a device-mapper device over a fixed partition", "0", "mapper", false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			devices := filepath.Join(root, "devices")
			block := filepath.Join(root, "dev", "block")
			for _, directory := range []string{
				filepath.Join(devices, "disk", "partition"),
				filepath.Join(devices, "mapper", "slaves"),
				block,
			} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			files := map[string]string{
				filepath.Join(devices, "disk", "removable"):   row.removable + "\n",
				filepath.Join(devices, "mapper", "removable"): "0\n",
			}
			for path, content := range files {
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			links := map[string]string{
				filepath.Join(block, "8:0"):                        filepath.Join(devices, "disk"),
				filepath.Join(block, "8:1"):                        filepath.Join(devices, "disk", "partition"),
				filepath.Join(block, "253:0"):                      filepath.Join(devices, "mapper"),
				filepath.Join(devices, "mapper", "slaves", "sda1"): filepath.Join(block, "8:1"),
			}
			for path, target := range links {
				if err := os.Symlink(target, path); err != nil {
					t.Skip("no symbolic links here:", err)
				}
			}
			device := map[string]string{"disk": "8:0", "partition": "8:1", "mapper": "253:0"}[row.judge]
			if got := removableAt(filepath.Join(block, device), maxStackDepth); got != row.want {
				t.Errorf("removableAt = %v, want %v", got, row.want)
			}
		})
	}
}
