// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// The names the permission table covers, as the package comment gives them.
const (
	bootstrapFileName  = "bootstrap.hadv"
	keyFileName        = "bootstrap.key"
	lockFileName       = "bootstrap.lock"
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

// readNames is the names in the bootstrap folder. A folder past the bound is an error: judging
// part of it would let the rest hide an item from Check.
func readNames(directory *os.File) ([]string, error) {
	names, err := directory.Readdirnames(maxFolderEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("bootstrap: reading the folder: %w", err)
	}
	if len(names) > maxFolderEntries {
		return nil, fmt.Errorf("bootstrap: the folder holds more than %d names, so hadv-setup did not make it", maxFolderEntries)
	}
	return names, nil
}

// looserRefusal is the refusal for the first finding by path. The findings come in no fixed order
// on Linux, so one choice for both platforms keeps the refusal the same every time.
func looserRefusal(findings []Finding) error {
	first := slices.MinFunc(findings, func(left, right Finding) int { return strings.Compare(left.Path, right.Path) })
	return &Refusal{Cause: LooserThanRule, Path: first.Path, Item: first.Item}
}
