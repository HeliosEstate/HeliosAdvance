// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program under key holder 4 as systemd starts it: a real unit, the page's own, run as hadv,
// whose credential systemd-creds sealed under the host's key from the raw 32-byte key and which
// loads it with LoadCredentialEncrypted=, so systemd unseals it and names its folder when it starts
// the service. The bootstrap folder holds no key file, or one with another key, so a program that
// took the key from anywhere but the credential would not start.
package main_test

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// credentialUnit installs a unit of the row's own on a row of the shared board whose bootstrap file
// is under key holder 4, seals the raw key as systemd's credential with systemd-creds under the
// host's key, and writes the unit to load it. With otherKey the bootstrap folder keeps a key file
// holding another key; without, it holds none. It returns the unit and the key.
func credentialUnit(t *testing.T, otherKey bool) (*systemdUnit, []byte) {
	t.Helper()
	settings := sharedRowSettings(t, telnetAt(23))
	unit := newUnit(t, settings)
	made := makeBootstrapFolder(t, []byte(settings.text(t)), "holder 4")
	unit.installFile(t, made.file, bootstrapFileName)
	if otherKey {
		_, other := newBootstrapKey(t)
		made.writeKey(t, other)
		unit.installFile(t, made.keyFile, keyFileName)
	} else {
		sudo(t, "rm", "-f", filepath.Join(unit.bootstrap, keyFileName))
	}
	raw := filepath.Join(t.TempDir(), "raw-key")
	if err := os.WriteFile(raw, made.key, 0o600); err != nil {
		t.Fatalf("writing the raw key: %v", err)
	}
	sealed := unit.library + "/" + heldKeyName + ".cred"
	sudo(t, "systemd-creds", "encrypt", "--with-key=host", "--name="+heldKeyName, raw, sealed)
	commandLine := strings.Join([]string{unit.program(), databaseOption, unit.bootstrap}, " ")
	settingsLines := "LoadCredentialEncrypted=" + heldKeyName + ":" + sealed + "\n"
	if testrun.Race {
		settingsLines += "Environment=GORACE=atexit_sleep_ms=0\n"
	}
	unitFile := filepath.Join(t.TempDir(), unit.name+".service")
	if err := os.WriteFile(unitFile, fmt.Appendf(nil, unitTemplate, commandLine, settingsLines), 0o600); err != nil {
		t.Fatalf("writing the unit: %v", err)
	}
	sudo(t, "install", "-m", "0644", "-o", "root", "-g", "root", unitFile, "/etc/systemd/system/"+unit.name+".service")
	sudo(t, "systemctl", "daemon-reload")
	return unit, made.key
}

// prepareUnits readies the machine for units of a row's own, as TestLinuxRootSystemd does: it
// takes what a dead run left, and makes the hadv account when the machine has none, removing it
// when the test ends.
func prepareUnits(t *testing.T) {
	t.Helper()
	if code, output := runSudo(t, "true"); code != 0 {
		t.Fatalf("these rows need root through sudo without a password: %s", output)
	}
	left := map[string]bool{}
	for _, pattern := range []string{"/etc/systemd/system/" + unitPrefix + "*.service", "/usr/local/lib/" + unitPrefix + "*", "/var/lib/" + unitPrefix + "*"} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("listing what a dead run left: %v", err)
		}
		for _, path := range found {
			left[strings.TrimSuffix(filepath.Base(path), ".service")] = true
		}
	}
	for name := range left {
		removeUnit(t, name)
	}
	if code, _ := runSudo(t, "id", "-u", daemonUser); code != 0 {
		sudo(t, "useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", daemonUser)
		t.Cleanup(func() {
			if code, output := runSudo(t, "userdel", daemonUser); code != 0 {
				t.Errorf("removing the account %s this run made: %d %s", daemonUser, code, output)
			}
		})
	}
}

// expectKeyNotInJournal fails the row when the journal holds the key raw, in hex or in base64.
func expectKeyNotInJournal(t *testing.T, journal string, key []byte) {
	t.Helper()
	for name, secret := range map[string]string{
		"the key's bytes": string(key), "the key in hex": hex.EncodeToString(key),
		"the key in base64": base64.StdEncoding.EncodeToString(key),
	} {
		if strings.Contains(journal, secret) {
			t.Fatalf("the journal holds %s:\n%s", name, journal)
		}
	}
}

// TestLinuxRootSystemdCredential runs alone, its rows one after the other: each installs a unit
// that listens on port 23, which only one program on the machine can hold. It needs root through
// sudo without a password, as CI's Linux runners allow.
func TestLinuxRootSystemdCredential(t *testing.T) { //nolint:paralleltest // it must run alone
	prepareUnits(t)

	t.Run("When the bootstrap file's key holder is 4, the engine shall take the bootstrap file's key only from the file `hadv-bootstrap-key` in the folder systemd names in `CREDENTIALS_DIRECTORY`.", func(t *testing.T) { //nolint:paralleltest // it must run alone
		for name, otherKey := range map[string]bool{"no key file": false, "a key file holding another key": true} {
			t.Run("a real unit as hadv loading the credential systemd-creds sealed from the raw key, and "+name+": active, 127.0.0.1:23 and [::1]:23 served, the journal's line started, the key not in it", func(t *testing.T) { //nolint:paralleltest // it must run alone
				unit, key := credentialUnit(t, otherKey)
				unit.start(t)
				unit.awaitActiveState(t, "active", time.Now().Add(testrun.Patient(testrun.HangBound)))
				expectServed(t, defaultIPv4Telnet)
				expectServed(t, defaultIPv6Telnet)
				journal := unit.awaitJournalLines(t, 1)
				expectStartedAtPort23(t, journal)
				expectKeyNotInJournal(t, journal, key)
			})
		}
	})
}
