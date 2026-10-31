// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

package testrun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// A run's folder holds everything one test binary makes on disk, servers and programs included,
// so that one removal takes it all, and a run that ended without removing its own, killed or
// timed out, leaves something the next run can find and take.
const (
	runPrefix = "hadv-test-run-"
	ownerName = "owner"
)

// Enter takes what dead runs left, makes this run's own folder with its owner written first, and
// points the temporary folder at it, for this binary and everything it starts. It is called first
// in a TestMain. swept is what it could not take of dead runs' folders, which this run need not
// stop for; err is its own folder not made, and then the run stops, since what it made would
// land outside any folder a run takes. The folder is returned whenever one was made, so Leave can
// still remove it.
func Enter() (folder string, swept, err error) {
	base := os.TempDir()
	swept = sweep(base)
	folder, err = os.MkdirTemp(base, runPrefix)
	if err != nil {
		return "", swept, err
	}
	if err := own(folder); err != nil {
		return folder, swept, err
	}
	for _, name := range []string{"TMP", "TEMP", "TMPDIR"} {
		if err := os.Setenv(name, folder); err != nil {
			return folder, swept, err
		}
	}
	return folder, swept, nil
}

// Windows may hold a file for a moment after what had it open has ended, a server's output file
// after pg_ctl stop returns or a program ended by a sweep among them, and nothing announces when
// it lets go. So remove checks again every removeInterval up to removeBound, and only what is
// still held then is reported: the check-again the no-sleep rule allows, a short interval, a
// stated bound and a report, waiting on a timer as the tests' pause does. testrun is test code,
// so the rule reaches it.
const (
	removeInterval = 100 * time.Millisecond
	removeBound    = 10 * time.Second
)

// Leave removes this run's folder, last in a TestMain. It first stops what still runs from it,
// as the next run would: on Linux a running server or program does not keep its folder from being
// removed, and would outlive it with nothing left to find it by.
func Leave(folder string) error {
	if folder == "" {
		return nil
	}
	return take(folder)
}

// remove removes a run's folder, checking again while Windows holds a file in it.
func remove(folder string) error {
	giveUp := time.Now().Add(removeBound)
	for {
		err := removeOnce(folder)
		if err == nil || time.Now().After(giveUp) {
			return err
		}
		<-time.NewTimer(removeInterval).C
	}
}

// removeOnce removes a run's folder with its owner last: a removal that fails partway, on a file
// Windows still holds, leaves the owner, so the next run finds the rest and takes it.
func removeOnce(folder string) error {
	// A folder swapped for a link to another, between one check and the next, would have that
	// other folder's contents removed: only a folder itself is.
	info, err := os.Lstat(folder)
	// Binaries started together sweep together, so another may have taken a dead run's folder.
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is no longer a folder", folder)
	}
	entries, err := os.ReadDir(folder)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if entry.Name() != ownerName {
			failures = append(failures, os.RemoveAll(filepath.Join(folder, entry.Name())))
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	return os.RemoveAll(folder)
}

// own writes the folder's owner, this process and when it started, whole under another name and
// then renamed, so a sweep never reads half an owner.
func own(folder string) error {
	started, err := processStart(os.Getpid())
	if err != nil {
		return err
	}
	partial := filepath.Join(folder, ownerName+".partial")
	if err := os.WriteFile(partial, fmt.Appendf(nil, "%d %d\n", os.Getpid(), started), 0o600); err != nil {
		return err
	}
	return os.Rename(partial, filepath.Join(folder, ownerName))
}

// sweep takes every run folder whose owner has ended. A folder whose owner is running, or cannot
// be told, or that has no owner yet, as another binary's has for a moment after it is made, is
// left alone.
func sweep(base string) error {
	entries, err := os.ReadDir(base)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), runPrefix) {
			continue
		}
		// Another user may make a folder of this name where the temporary folder is shared, and
		// what this sweep does to a folder it does as this user.
		if info, err := entry.Info(); err != nil || !mine(info) {
			continue
		}
		folder := filepath.Join(base, entry.Name())
		if ownerEnded(folder) {
			failures = append(failures, take(folder))
		}
	}
	return errors.Join(failures...)
}

// ownerEnded is whether the folder's owner has ended: none has its number, or the one that has it
// started at another moment, its number having been given again.
func ownerEnded(folder string) bool {
	text, err := readSmall(filepath.Join(folder, ownerName))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(text))
	if len(fields) != 2 {
		return false
	}
	processID, idErr := strconv.Atoi(fields[0])
	started, startErr := strconv.ParseInt(fields[1], 10, 64)
	if idErr != nil || startErr != nil {
		return false
	}
	now, err := processStart(processID)
	if err != nil {
		return processGone(err)
	}
	return now != started
}

// smallFileBytes bounds what readSmall reads: an owner, or a process's stat on Linux, is far less.
const smallFileBytes = 4096

// readSmall reads a file of at most smallFileBytes; a larger one is not what was asked for.
func readSmall(path string) (text []byte, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	buffer := make([]byte, smallFileBytes)
	n, err := io.ReadFull(file, buffer)
	switch {
	case err == nil:
		return nil, fmt.Errorf("%s is larger than %d bytes", path, smallFileBytes)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return buffer[:n], nil
	default:
		return nil, err
	}
}

// take ends what a dead run left running in its folder, then removes the folder. A stop that
// failed leaves the folder and its owner, the only record of what still runs, for the next run.
func take(folder string) error {
	if err := stop(folder); err != nil {
		return err
	}
	return remove(folder)
}

// stop stops every server and program still running from a run's folder.
func stop(folder string) error {
	return errors.Join(stopServers(folder), stopPrograms(folder))
}

// stopServers stops every PostgreSQL server whose data folder is in the run's folder: a server
// started detached outlives the binary that started it.
func stopServers(folder string) error {
	var failures []error
	walked := filepath.WalkDir(folder, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			failures = append(failures, err)
			return nil
		}
		if entry.IsDir() || entry.Name() != "postmaster.pid" {
			return nil
		}
		data := filepath.Dir(path)
		running, err := serverRunsIn(data)
		if err != nil {
			failures = append(failures, err)
			return nil
		}
		if !running {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := exec.CommandContext(ctx, "pg_ctl", "stop", "-D", data, "-m", "immediate", "-w", "-t", "60").Run(); err != nil {
			failures = append(failures, fmt.Errorf("stopping the server in %s: %w", data, err))
		}
		return nil
	})
	return errors.Join(append(failures, walked)...)
}
