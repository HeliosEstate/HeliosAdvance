// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package servicemanager

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
)

var notifyOnce sync.Once

// notifySystemdReady drops a message that cannot be sent: systemd's own start timeout then marks
// the start failed. Any name but a path or an abstract name is left unanswered, as the contract
// says.
func notifySystemdReady() {
	notifyOnce.Do(func() {
		socket, _ := os.LookupEnv("NOTIFY_SOCKET")
		if !strings.HasPrefix(socket, "/") && !strings.HasPrefix(socket, "@") {
			return
		}
		// An abstract name starts with a NUL byte on the wire, which the environment cannot hold.
		if socket[0] == '@' {
			socket = "\x00" + socket[1:]
		}
		if sendReady(socket) != nil {
			return
		}
	})
}

func sendReady(socket string) error {
	connection, err := (&net.Dialer{}).DialContext(context.Background(), "unixgram", socket)
	if err != nil {
		return err
	}
	_, err = connection.Write([]byte("READY=1"))
	return errors.Join(err, connection.Close())
}
