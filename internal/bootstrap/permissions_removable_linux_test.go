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
	diskName       = "disk"
	partitionName  = "sda1"
	markerName     = "partition"
	mdName         = "md"
	mdPartition    = "mdpartition"
	mapperName     = "mapper"
	mapperTopName  = "mappertop"
	parentName     = "parent"
	emptyFlagName  = "emptyflag"
	removableFile  = "removable"
	slavesDirName  = "slaves"
	sysfsRemovable = "1"
)

// TestRemovableAt proves the Removable rule reaches a removable disk as sysfs lays it out. In sysfs
// /sys/dev/block/<major>:<minor> is a symbolic link to the device's real directory, and a partition
// directory holds a partition file. A partition of an md device sits inside the device's directory;
// a device-mapper device is a separate directory with a removable file of its own reading 0 and
// slaves/ entries that are relative links to the device beneath.
func TestRemovableAt(t *testing.T) {
	t.Parallel()
	t.Run(lineCheckFolder, func(t *testing.T) {
		t.Parallel()
		rows := []struct {
			name      string
			removable string // what the disk's removable file reads
			judge     string // the device to judge: a link from block/, as the kernel gives it
			want      bool
		}{
			{"a removable disk", sysfsRemovable, diskName, true},
			{"a fixed disk", "0", diskName, false},
			{"a partition of a removable disk", sysfsRemovable, partitionName, true},
			{"a partition of a fixed disk", "0", partitionName, false},
			{"an md device over a removable partition", sysfsRemovable, mdName, true},
			{"an md device over a fixed partition", "0", mdName, false},
			{"a partition of an md device over a removable partition", sysfsRemovable, mdPartition, true},
			{"a partition of an md device over a fixed partition", "0", mdPartition, false},
			{"a device-mapper device over a device-mapper device over a removable partition", sysfsRemovable, mapperTopName, true},
			{"a device-mapper device over a device-mapper device over a fixed partition", "0", mapperTopName, false},
			{"a disk whose removable file is empty, in a removable directory, is judged as itself", sysfsRemovable, emptyFlagName, false},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				root := t.TempDir()
				devices := filepath.Join(root, "devices")
				block := filepath.Join(root, "dev", "block")
				for _, directory := range []string{
					filepath.Join(devices, diskName, partitionName),
					filepath.Join(devices, mdName, slavesDirName),
					filepath.Join(devices, mdName, mdPartition),
					filepath.Join(devices, mapperName, slavesDirName),
					filepath.Join(devices, mapperTopName, slavesDirName),
					filepath.Join(devices, parentName, emptyFlagName),
					block,
				} {
					if err := os.MkdirAll(directory, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				files := map[string]string{
					filepath.Join(devices, diskName, removableFile):                  row.removable + "\n",
					filepath.Join(devices, diskName, partitionName, markerName):      "1\n",
					filepath.Join(devices, mdName, removableFile):                    "0\n",
					filepath.Join(devices, mdName, mdPartition, markerName):          "1\n",
					filepath.Join(devices, mapperName, removableFile):                "0\n",
					filepath.Join(devices, mapperTopName, removableFile):             "0\n",
					filepath.Join(devices, parentName, removableFile):                row.removable + "\n",
					filepath.Join(devices, parentName, emptyFlagName, removableFile): "",
				}
				for path, content := range files {
					if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				links := map[string]string{
					filepath.Join(block, "8:0"):   filepath.Join(devices, diskName),
					filepath.Join(block, "8:1"):   filepath.Join(devices, diskName, partitionName),
					filepath.Join(block, "9:0"):   filepath.Join(devices, mdName),
					filepath.Join(block, "9:1"):   filepath.Join(devices, mdName, mdPartition),
					filepath.Join(block, "253:0"): filepath.Join(devices, mapperName),
					filepath.Join(block, "253:1"): filepath.Join(devices, mapperTopName),
					filepath.Join(block, "7:0"):   filepath.Join(devices, parentName, emptyFlagName),
					// the kernel's slaves/ entries: relative, straight to the device beneath
					filepath.Join(devices, mdName, slavesDirName, "sda1"):        filepath.Join("..", "..", diskName, partitionName),
					filepath.Join(devices, mapperName, slavesDirName, "sda1"):    filepath.Join("..", "..", diskName, partitionName),
					filepath.Join(devices, mapperTopName, slavesDirName, "dm-0"): filepath.Join("..", "..", mapperName),
				}
				for path, target := range links {
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				}
				device := map[string]string{
					diskName: "8:0", partitionName: "8:1", mdName: "9:0", mdPartition: "9:1",
					mapperTopName: "253:1", emptyFlagName: "7:0",
				}[row.judge]
				if got := removableAt(filepath.Join(block, device), maxStackDepth); got != row.want {
					t.Errorf("removableAt = %v, want %v", got, row.want)
				}
			})
		}
	})
}
