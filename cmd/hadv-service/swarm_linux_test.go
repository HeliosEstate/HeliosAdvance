// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The program under key holder 5 as Swarm runs it: a real single-node swarm, the engine built for
// the row with cgo off into an image from scratch, so nothing is pulled, and run as a service on
// the host's network, granted the secret with the engine's own user ID and mode 0400 as the page's
// stack file would. The bootstrap folder is bound into the container read-only at its own path and
// holds no key file, so an engine that took the key from anywhere but the secret would not start.
// An image from scratch has no temporary folder, which the engine writes to as it prepares its
// database settings, so the service is given one in memory.
// A swarm found active is taken only when it runs nothing but test runs' services; otherwise the
// row cannot run there.
package main_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliosestate/heliosadvance/internal/testrun"
)

// swarmPoll is how often the row reads the service's log and its task's state: Docker announces
// neither to a reader that does not follow its events.
const swarmPoll = 200 * time.Millisecond

// docker runs a docker command, bounded by the hang bound, and returns its output; a failure fails
// the row, or, in a cleanup, is reported.
func docker(t *testing.T, arguments ...string) string {
	t.Helper()
	code, output := runDocker(t, arguments...)
	if code != 0 {
		t.Fatalf("docker %s ended %d: %s", strings.Join(arguments, " "), code, output)
	}
	return output
}

// runDocker runs a docker command, bounded by the hang bound, and returns its exit code and output.
// Its context is not the row's, which has ended by the time a cleanup runs.
func runDocker(t *testing.T, arguments ...string) (int, string) {
	t.Helper()
	bound := testrun.Patient(testrun.HangBound)
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", arguments...)
	command.WaitDelay = bound
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return sudoTimedOut, fmt.Sprintf("docker %s had not ended within %v: %s", strings.Join(arguments, " "), bound, output)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(output)
	}
	if err != nil {
		t.Fatalf("running docker %s: %v", strings.Join(arguments, " "), err)
	}
	return 0, string(output)
}

// takeSwarm readies a swarm for the row: it makes one on loopback, left when the row ends, or takes
// one a dead run left, which runs nothing but test runs' services, removing those.
func takeSwarm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("Docker, the Swarm row's oracle, is not installed: %v", err)
	}
	state := strings.TrimSpace(docker(t, "info", "--format", "{{.Swarm.LocalNodeState}}"))
	if state == "active" {
		for name := range strings.FieldsSeq(docker(t, "service", "ls", "--format", "{{.Name}}")) {
			if !strings.HasPrefix(name, unitPrefix) {
				t.Fatalf("this machine's swarm runs the service %s, not a test run's, so this row cannot run here", name)
			}
			removeService(t, name)
		}
	} else {
		docker(t, "swarm", "init", "--advertise-addr", "127.0.0.1")
	}
	t.Cleanup(func() {
		if code, output := runDocker(t, "swarm", "leave", "--force"); code != 0 {
			t.Errorf("leaving the swarm: %s", output)
		}
	})
}

// removeService removes a service and waits, up to the hang bound, until no container of it is
// left, so no process of it still runs from the run's own folder when the run ends.
func removeService(t *testing.T, name string) {
	t.Helper()
	if code, output := runDocker(t, "service", "rm", name); code != 0 {
		t.Errorf("removing the service %s: %s", name, output)
	}
	giveUp := time.Now().Add(testrun.Patient(testrun.HangBound))
	for {
		_, left := runDocker(t, "ps", "-a", "-q", "--filter", "label=com.docker.swarm.service.name="+name)
		if strings.TrimSpace(left) == "" {
			return
		}
		if time.Now().After(giveUp) {
			t.Errorf("containers of the service %s were still there %v on: %s", name, testrun.Patient(testrun.HangBound), left)
			return
		}
		pause(t, swarmPoll)
	}
}

// engineImage builds the program with cgo off, so it needs no library in an image from scratch, and
// an image of it with the shipped lang folder beside it, removed when the row ends; it returns the
// image's name.
func engineImage(t *testing.T, name string) string {
	t.Helper()
	folder := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*testrun.Patient(testrun.HangBound))
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(folder, "hadv-service"), ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the program for the image: %v: %s", err, output)
	}
	// The engine refuses to start without its language files beside it.
	if err := os.CopyFS(filepath.Join(folder, langFolder), os.DirFS(shippedLang)); err != nil {
		t.Fatalf("placing the shipped lang folder beside the program: %v", err)
	}
	dockerfile := "FROM scratch\nCOPY hadv-service /hadv-service\nCOPY " + langFolder + " /" + langFolder + "\nENTRYPOINT [\"/hadv-service\"]\n"
	if err := os.WriteFile(filepath.Join(folder, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatalf("writing the Dockerfile: %v", err)
	}
	image := name + ":test"
	docker(t, "build", "--quiet", "--tag", image, folder)
	t.Cleanup(func() {
		if code, output := runDocker(t, "image", "rm", "--force", image); code != 0 {
			t.Errorf("removing the image %s: %s", image, output)
		}
	})
	return image
}

// TestOracleSwarm runs alone: a swarm is one for the whole machine.
func TestOracleSwarm(t *testing.T) { //nolint:paralleltest // a swarm is one for the whole machine
	t.Run("When the bootstrap file's key holder is 5, the engine shall take the bootstrap file's key only from the Swarm secret `/run/secrets/hadv-bootstrap-key`.", func(t *testing.T) { //nolint:paralleltest // a swarm is one for the whole machine
		t.Run("a real single-node swarm service, granted the secret at mode 0400 with the engine's own user ID, no key file: its log's line started, each listener it names served, the key not in its log", func(t *testing.T) { //nolint:paralleltest // a swarm is one for the whole machine
			takeSwarm(t)
			name := unitPrefix + strings.ToLower(rand.Text()[:10])
			image := engineImage(t, name)
			made := makeBootstrapFolder(t, []byte(sharedRowSettings(t, telnetAt(0)).text(t)), "holder 5")
			removeFile(t, made.keyFile)
			secretFile := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(secretFile, []byte(made.keyText), 0o600); err != nil {
				t.Fatalf("writing the secret: %v", err)
			}
			docker(t, "secret", "create", name, secretFile)
			t.Cleanup(func() {
				if code, output := runDocker(t, "secret", "rm", name); code != 0 {
					t.Errorf("removing the secret %s: %s", name, output)
				}
			})
			uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
			docker(t, "service", "create", "--detach", "--name", name, "--no-resolve-image", "--network", "host",
				"--restart-condition", "none", "--user", uid+":"+gid,
				"--mount", "type=bind,"+csvField("source="+made.path)+","+csvField("target="+made.path)+",readonly",
				"--mount", "type=tmpfs,target=/tmp",
				"--secret", "source="+name+",target="+heldKeyName+",uid="+uid+",gid="+gid+",mode=0400",
				image, databaseOption, made.path)
			t.Cleanup(func() { removeService(t, name) })
			log := awaitServiceLog(t, name)
			values := expectLogText(t, log, "started")
			for _, address := range telnetAlone(t, strings.Split(values[0], ",")) {
				expectServed(t, address)
			}
			made.expectKeyNotIn(t, log)
		})
	})
}

// csvField quotes one field of an option Docker reads as comma-separated values, such as
// --mount's, so a path holding a comma, as a row's temporary folder does, stays one field.
func csvField(field string) string {
	return `"` + strings.ReplaceAll(field, `"`, `""`) + `"`
}

// awaitServiceLog waits, up to the hang bound, for the service's log to hold a whole line, and
// returns it. A task that ends meanwhile fails the row at once, with its state and log.
func awaitServiceLog(t *testing.T, name string) string {
	t.Helper()
	giveUp := time.Now().Add(testrun.Patient(testrun.HangBound))
	for {
		log := docker(t, "service", "logs", "--raw", name)
		if strings.Contains(log, "\n") {
			return log
		}
		state := strings.TrimSpace(docker(t, "service", "ps", "--no-trunc", "--format", "{{.CurrentState}} {{.Error}}", name))
		for _, ended := range []string{"Failed", "Rejected", "Complete", "Shutdown"} {
			if strings.HasPrefix(state, ended) {
				t.Fatalf("the service's task ended, %q, before its log held a line: %q", state, log)
			}
		}
		if time.Now().After(giveUp) {
			t.Fatalf("the service's log held no line %v on; its task: %q", testrun.Patient(testrun.HangBound), state)
		}
		pause(t, swarmPoll)
	}
}
