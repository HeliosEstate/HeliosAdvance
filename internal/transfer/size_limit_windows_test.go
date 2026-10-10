// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package transfer_test

import (
	"os"
	"syscall"
)

// fsctlSetSparse is FSCTL_SET_SPARSE, the control code that marks a file sparse on NTFS.
const fsctlSetSparse = 0x000900c4

// markSparse marks file sparse. NTFS otherwise reserves a file's whole length the moment it
// is extended, so each of the rows' 4 GiB files would hold 4 GiB of disk until removed.
func markSparse(file *os.File) error {
	var returned uint32
	return syscall.DeviceIoControl(syscall.Handle(file.Fd()), fsctlSetSparse, nil, 0, nil, 0, &returned, nil)
}
