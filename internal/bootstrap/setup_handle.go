// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package bootstrap

import (
	"context"
	"os"
	"sync"
)

type setupHandle struct {
	mutex   sync.Mutex
	file    *bootstrapFile
	lock    *os.File
	holding Holding
}

func (handle *setupHandle) Fields() Fields {
	handle.mutex.Lock()
	defer handle.mutex.Unlock()
	if handle.file == nil {
		return Fields{}
	}
	return handle.file.fields()
}
func (handle *setupHandle) Holding() Holding { return handle.holding }
func (handle *setupHandle) Rewrite(context.Context, Fields) error {
	return &Refusal{Cause: RewriteFailed}
}
func (handle *setupHandle) RewriteFailure() RewriteFailure { return RewriteFailure{} }
func (handle *setupHandle) Close() {
	handle.mutex.Lock()
	defer handle.mutex.Unlock()
	if handle.file == nil {
		return
	}
	for index := range handle.file.records {
		clear(handle.file.records[index].data)
	}
	handle.file = nil
	releaseSetupLock(handle.lock)
	handle.lock = nil
}

// serviceHandle is the handle UnlockForService returns: the unlock's own, with the two
// vault-key writes.
type serviceHandle struct{ *setupHandle }

func (serviceHandle) AddVaultKey(context.Context, VaultKey) error {
	return &Refusal{Cause: RewriteFailed}
}
func (serviceHandle) RemoveVaultKey(context.Context, uint32) error {
	return &Refusal{Cause: RewriteFailed}
}
