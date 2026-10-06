// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// Directory names under the fake sysfs devices/ tree.
const (
	diskName            = "disk"
	partitionName       = "partition"
	mapperName          = "mapper"
	mapperPartitionName = "mapperpartition"
)

// TestRemovableAt proves the Removable rule reaches a removable disk as sysfs lays it out. Each row
// proves the folder rule line under Check: "If the folder breaks a folder rule, then Check shall
// refuse with FolderRefused, naming the rule." In sysfs /sys/dev/block/<major>:<minor> is a symbolic
// link to the device's real directory, a partition's directory sits inside its disk's, and a
// device-mapper device has a removable file of its own reading 0 and slaves/ entries that are
// relative links to the partitions it is built on.
func TestRemovableAt(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name      string
		removable string // what the disk's removable file reads
		judge     string // the device to judge: a link from block/, as the kernel gives it
		want      bool
	}{
		{"a removable disk", "1", diskName, true},
		{"a fixed disk", "0", diskName, false},
		{"a partition of a removable disk", "1", partitionName, true},
		{"a partition of a fixed disk", "0", partitionName, false},
		{"a device-mapper device over a removable partition", "1", mapperName, true},
		{"a device-mapper device over a fixed partition", "0", mapperName, false},
		{"a partition of a device-mapper device over a removable partition", "1", mapperPartitionName, true},
		{"a partition of a device-mapper device over a fixed partition", "0", mapperPartitionName, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			devices := filepath.Join(root, "devices")
			block := filepath.Join(root, "dev", "block")
			for _, directory := range []string{
				filepath.Join(devices, diskName, partitionName),
				filepath.Join(devices, mapperName, "slaves"),
				filepath.Join(devices, mapperName, mapperPartitionName),
				block,
			} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			files := map[string]string{
				filepath.Join(devices, diskName, "removable"):   row.removable + "\n",
				filepath.Join(devices, mapperName, "removable"): "0\n",
			}
			for path, content := range files {
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			links := map[string]string{
				filepath.Join(block, "8:0"):   filepath.Join(devices, diskName),
				filepath.Join(block, "8:1"):   filepath.Join(devices, diskName, partitionName),
				filepath.Join(block, "253:0"): filepath.Join(devices, mapperName),
				filepath.Join(block, "253:1"): filepath.Join(devices, mapperName, mapperPartitionName),
				// the kernel's slaves/ entry: relative, straight to the partition under devices/
				filepath.Join(devices, mapperName, "slaves", "sda1"): filepath.Join("..", "..", diskName, partitionName),
			}
			for path, target := range links {
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			device := map[string]string{
				diskName: "8:0", partitionName: "8:1", mapperName: "253:0", mapperPartitionName: "253:1",
			}[row.judge]
			if got := removableAt(filepath.Join(block, device), maxStackDepth); got != row.want {
				t.Errorf("removableAt = %v, want %v", got, row.want)
			}
		})
	}
}
