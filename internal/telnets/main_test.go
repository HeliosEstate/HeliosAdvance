// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The Telnet over TLS unit called through its exported names: ReadCertificate on files openssl
// makes for the run, and Accept over loopback, with OpenSSL's s_client or QA's own Telnet caller
// over a crypto/tls client on the other end. TestMain gives the run its own folder, since the
// rows start openssl.
package telnets_test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// opensslPath is the openssl the rows run, found once; a missing one fails every row that needs
// it, never skips it.
var (
	opensslPath    string
	opensslFailure error
)

func TestMain(tests *testing.M) {
	runFolder, swept, err := testrun.Enter()
	if swept != nil {
		fmt.Fprintf(os.Stderr, "what dead runs left: %v\n", swept)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "the run's own folder: %v\n", err)
		if err := testrun.Leave(runFolder); err != nil {
			fmt.Fprintf(os.Stderr, "removing the run's own folder: %v\n", err)
		}
		os.Exit(1)
	}
	opensslPath, opensslFailure = exec.LookPath("openssl")
	code := tests.Run()
	// Logged, not failed: whether Windows has let go of every file by now is its timing, and the
	// next run takes what is left.
	if err := testrun.Leave(runFolder); err != nil {
		fmt.Fprintf(os.Stderr, "removing the run's own folder: %v\n", err)
	}
	os.Exit(code)
}
