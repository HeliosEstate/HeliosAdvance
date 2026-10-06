// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

// The names the permission table covers, as the package comment gives them.
const (
	bootstrapFileName  = "bootstrap.hadv"
	keyFileName        = "bootstrap.key"
	machineKeyPairName = "heliosadvance-bootstrap-key"
)

// maxFolderEntries bounds how many names of the bootstrap folder are read: it holds a handful
// of files, so a folder with more is not one hadv-setup made.
const maxFolderEntries = 1024

// itemOf is which item a file in the bootstrap folder is, by its name.
func itemOf(name string) Item {
	switch name {
	case bootstrapFileName:
		return ItemFile
	case keyFileName:
		return ItemKeyFile
	}
	return ItemOtherFile
}
