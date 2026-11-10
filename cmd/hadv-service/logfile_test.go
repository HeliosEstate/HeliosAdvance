// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The local log's place, on every runner: standard output without a log file, the file named on
// the command line with one, appended to across runs, and the refusal when that file will not
// open. Each row starts the built program as the runner's own user and reads the file and the
// program's standard output and standard error from outside.
package main_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// logFileOption is the option that names the log file, as the page names it.
const logFileOption = "-log-file"

// sysopLine is a line already in a log file before the engine first opens it, which the engine
// must leave as it is.
const sysopLine = "a line the sysop wrote before the engine ran\n"

// readLogFile waits until the log file holds count whole lines after skip bytes, and returns
// those lines. A program that exits first, or lines that do not come by the start limit, fail the
// row. The file is read again on a timer: nothing announces a write to it.
func readLogFile(t *testing.T, program *run, path string, skip, count int) []string {
	t.Helper()
	giveUp := time.Now().Add(startLimit)
	for {
		contents, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("reading the log file: %v", err)
		}
		if len(contents) >= skip {
			text := string(contents[skip:])
			if strings.Count(text, "\n") >= count {
				return strings.SplitAfterN(text, "\n", count+1)[:count]
			}
		}
		select {
		case <-program.exited:
			t.Fatalf("the program exited with %d before the log file held %d lines; the file: %q; its standard output: %q",
				program.code(), count, contents, program.text())
		default:
		}
		if time.Now().After(giveUp) {
			t.Fatalf("the log file held %q %v after the start, want %d lines", contents, startLimit, count)
		}
		pause(t, 20*time.Millisecond)
	}
}

// expectStartedLine checks a line of the log file is a started line naming Telnet at 127.0.0.1
// and at ::1, as a program started with -port 0 and nothing else names it.
func expectStartedLine(t *testing.T, line string) {
	t.Helper()
	value, found := strings.CutPrefix(line, "started=")
	if !found || !strings.HasSuffix(value, "\n") {
		t.Fatalf("the log file's line is %q, want a started line ending in LF", line)
	}
	loopbackPorts(t, telnetAlone(t, strings.Split(strings.TrimSuffix(value, "\n"), ",")))
}

// expectNamesLogFile checks a refusal over the log file says so: it names the log file, the option
// that names it, or its path, as a refusal over the bootstrap folder names that.
func expectNamesLogFile(t *testing.T, reason, path string) {
	t.Helper()
	lower := strings.ToLower(reason)
	if !strings.Contains(lower, "log file") && !strings.Contains(lower, logFileOption) && !strings.Contains(reason, path) {
		t.Fatalf("the reason %q does not name the log file it could not open", reason)
	}
}

// stopProgram sends the program the stop signal and waits for it to exit.
func stopProgram(t *testing.T, program *run, send func(*testing.T, *run) (time.Time, time.Time)) {
	t.Helper()
	_, sentBy := send(t, program)
	program.exit(t, sentBy.Add(testrun.Patient(testrun.HangBound)))
}

// expectNothingWritten checks, once the program has exited, that it wrote nothing to the stream
// named.
func expectNothingWritten(t *testing.T, name, text string) {
	t.Helper()
	if text != "" {
		t.Fatalf("the program wrote %q to %s, want nothing", text, name)
	}
}

// startLogged starts the program on a row of its own with -port 0 and the log file at path,
// readies the stop signal first, and waits for the log file to hold the started line after skip
// bytes. It stops the program and returns the file's whole contents.
func startLogged(t *testing.T, path string, skip int) []byte {
	t.Helper()
	send := stopSignals()[0].prepare(t)
	program := startProgram(t, portOption, "0", logFileOption, path)
	expectStartedLine(t, readLogFile(t, program, path, skip, 1)[0])
	stopProgram(t, program, send)
	expectNothingWritten(t, "standard output", program.text())
	expectNothingWritten(t, "standard error", program.standardError.String())
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the log file after the stop: %v", err)
	}
	return contents
}

func TestLogFile(t *testing.T) {
	t.Parallel()

	t.Run("The engine shall write the local log to standard output or, when the sysop passes a log file on the command line, appended to that file.", func(t *testing.T) {
		t.Parallel()
		// Standard error empty shows the log went to standard output alone, not to both, as the
		// engine's earlier parts wrote it to standard error.
		t.Run("no log file: the started line on standard output, and nothing on standard error after a stop", func(t *testing.T) {
			t.Parallel()
			send := stopSignals()[0].prepare(t)
			program := startProgram(t, portOption, "0")
			program.listening(t)
			stopProgram(t, program, send)
			program.expectLog(t, "started")
			expectNothingWritten(t, "standard error", program.standardError.String())
		})
		t.Run("a log file not yet there: after a start and a stop it holds exactly the started line, and nothing is on standard output or standard error", func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "hadv.log")
			contents := startLogged(t, path, 0)
			if strings.Count(string(contents), "\n") != 1 {
				t.Fatalf("the log file holds %q, want the started line alone", contents)
			}
		})
		t.Run("a log file holding a line of the sysop's: after two starts and stops it holds that line, then the first run's line, then the second's, each byte as before", func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "hadv.log")
			if err := os.WriteFile(path, []byte(sysopLine), 0o600); err != nil {
				t.Fatalf("writing the sysop's line: %v", err)
			}
			first := startLogged(t, path, len(sysopLine))
			if !strings.HasPrefix(string(first), sysopLine) || strings.Count(string(first), "\n") != 2 {
				t.Fatalf("after the first run the log file holds %q, want the sysop's line and one started line", first)
			}
			second := startLogged(t, path, len(first))
			if !strings.HasPrefix(string(second), string(first)) || strings.Count(string(second), "\n") != 3 {
				t.Fatalf("after the second run the log file holds %q, want %q and one started line after it", second, first)
			}
		})
		t.Run("a refusal, no bootstrap folder, with a log file: its start_failed line in the file, nothing on standard output, a non-zero exit", func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "hadv.log")
			program := startBare(t, portOption, "0", logFileOption, path)
			code, _ := program.exit(t, time.Now().Add(startLimit))
			if code == 0 {
				t.Fatalf("the program refused to start but exited with 0")
			}
			expectNothingWritten(t, "standard output", program.text())
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading the log file: %v", err)
			}
			if want := "start_failed=" + noFileReason(t) + "\n"; string(contents) != want {
				t.Fatalf("the log file holds %q, want the refusal without a log file, %q", contents, want)
			}
		})
	})

	t.Run("If opening the log file for appending fails, then the engine shall write one `start_failed` line to standard output saying so, and exit with a non-zero code.", func(t *testing.T) {
		t.Parallel()
		cases := map[string]func(t *testing.T) (string, func(t *testing.T)){
			// A file where the path needs a folder: no engine can make the folder there, so the
			// open fails whatever the engine does first.
			"a path under a file, not a folder": func(t *testing.T) (string, func(t *testing.T)) {
				t.Helper()
				file := filepath.Join(t.TempDir(), "logs")
				if err := os.WriteFile(file, []byte(sysopLine), 0o600); err != nil {
					t.Fatalf("writing the file: %v", err)
				}
				return filepath.Join(file, "hadv.log"), func(t *testing.T) {
					t.Helper()
					if found, err := os.ReadFile(file); err != nil || string(found) != sysopLine {
						t.Fatalf("the file holds %q (%v) after the refusal, want %q as it was", found, err, sysopLine)
					}
				}
			},
			"a path that names a folder": func(t *testing.T) (string, func(t *testing.T)) {
				t.Helper()
				folder := filepath.Join(t.TempDir(), "hadv.log")
				if err := os.Mkdir(folder, 0o700); err != nil {
					t.Fatalf("making the folder: %v", err)
				}
				return folder, func(t *testing.T) {
					t.Helper()
					entries, err := os.ReadDir(folder)
					if err != nil || len(entries) != 0 {
						t.Fatalf("the folder holds %v after the refusal (%v), want nothing", entries, err)
					}
				}
			},
		}
		for name, prepare := range unopenableLogFiles() {
			cases[name] = prepare
		}
		for name, prepare := range cases {
			t.Run(name+": one start_failed line on standard output naming the log file, a reason of its own, a non-zero exit, and the path left as it was", func(t *testing.T) {
				t.Parallel()
				path, unchanged := prepare(t)
				reason := startProgram(t, portOption, "0", logFileOption, path).expectRefusal(t)
				expectNamesLogFile(t, reason, path)
				expectOwnReason(t, reason, noFileReason(t), "no bootstrap folder")
				unchanged(t)
			})
		}
	})
}
