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
	key     []byte
	lock    *os.File
	holding Holding
}

func (handle *setupHandle) Fields() Fields {
	handle.mutex.Lock()
	defer handle.mutex.Unlock()
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
	clear(handle.key)
	handle.file, handle.key = nil, nil
	releaseSetupLock(handle.lock)
	handle.lock = nil
}
