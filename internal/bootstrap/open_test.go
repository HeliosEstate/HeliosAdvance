// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// The approved tests for issue #148, open under a key file or a Swarm secret, written by the
// QA session from the issue's lines. Each group of rows quotes, word for word, the line its
// rows prove. Open has key holders 4 and 5 only on Linux, and the Swarm secret's path is fixed
// and needs root, so the Linux rows run as root in the bootstrap file oracle's own image,
// through TestOpenLinuxRowsInContainer, from any machine with Docker; the rows that need an
// account the folder's permissions refuse run in the same container as the account nobody.
// Every wrong file comes from the oracle at test time; the kept samples are opened as they
// are. The rows on a missing or unreadable folder or file need no key holder, and run on
// Windows too. Docker is required, not optional: a missing docker is a failure, never a skip.
package bootstrap

import (
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The lines the rows on both platforms prove, word for word.
const (
	lineFolderUnreadable = "If the bootstrap folder is there and opening it fails, then the bootstrap package shall return ErrUnreadable with the OS's cause beneath it."
	linePlace            = "When the bootstrap package returns ErrNotFound or ErrUnreadable, the error shall name whether the bootstrap folder or bootstrap.hadv is the cause."
	lineNotFound         = "If the bootstrap folder or bootstrap.hadv is not there, then open shall return ErrNotFound."
	lineFileUnreadable   = "If bootstrap.hadv is there and opening or reading it fails, then open shall return ErrUnreadable with the OS's cause beneath it."
	lineTooLarge         = "If bootstrap.hadv holds more than 65,536 bytes, then open shall return ErrFormat, having read at most 65,537 bytes of it."
)

// The rows more than one line shares on both platforms: one name for each case, so the same
// case reads the same under every line.
const (
	rowFolderMissing = "no bootstrap folder"
	rowFileMissing   = "a bootstrap folder with no bootstrap.hadv"
	rowFileForFolder = "a file where the bootstrap folder should be"
	rowFolderForFile = "a folder named bootstrap.hadv"
)

// The kept samples the rows open by name, without their extension.
const (
	sampleKeyFile      = "keyholder-4"
	sampleSwarmSecret  = "keyholder-5"
	sampleTwoVaultKeys = "two-vault-keys"
	sampleUnknown      = "unknown-record"
)

// Where the rows find what they need. The samples are read from the package folder, or from
// the copy the container is given at the same relative path.
const (
	samples     = "testdata/format-1"
	oracleImage = "heliosestate/bootstrap-file-oracle:0.1"
	rowAccount  = ServiceAccount("hadv-service") // open uses it for key holder 2 only
)

// TestOpenLinuxRowsInContainer runs the Linux rows in the bootstrap file oracle's image: the
// package's tests built for Linux, run as root, then the rows that need permissions to refuse
// run as the account nobody, through setpriv.
func TestOpenLinuxRowsInContainer(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is required for the Linux rows: %v", err)
	}
	architecture, err := exec.CommandContext(t.Context(), "docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		t.Fatalf("docker version: %v", err)
	}
	dir := t.TempDir()
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", filepath.Join(dir, "bootstrap.test"), ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+strings.TrimSpace(string(architecture)), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the tests for Linux: %v\n%s", err, out)
	}
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	// The binary is copied out of the mount, which may be the test's own folder and closed to
	// nobody, into /tmp, where nobody can run it.
	script := `status=0
cp /rows-binary/bootstrap.test /tmp/rows.test && chmod 755 /tmp/rows.test || exit 1
/tmp/rows.test -test.v -test.count=1 -test.run '^TestOpenLinuxAsRoot$' -bootstrap.container || status=1
setpriv --reuid=65534 --regid=65534 --clear-groups /tmp/rows.test -test.v -test.count=1 -test.run '^TestOpenLinuxAsNobody$' -bootstrap.container || status=1
exit $status`
	out, err := exec.CommandContext(t.Context(), "docker", "run", "--rm",
		"-v", dir+":/rows-binary:ro", "-v", testdata+":/rows/testdata:ro", "-w", "/rows",
		oracleImage, "sh", "-c", script).CombinedOutput()
	t.Logf("the rows:\n%s", out)
	if err != nil {
		t.Fatalf("the rows failed: %v", err)
	}
}

// TestReadFileLimit proves the size limit's read at the reader itself, which counts every byte
// read.
func TestReadFileLimit(t *testing.T) {
	t.Parallel()
	t.Run(lineTooLarge, func(t *testing.T) {
		t.Parallel()
		t.Run("a reader that never ends", func(t *testing.T) {
			t.Parallel()
			source := &countingReader{size: -1}
			_, err := readFile(source)
			wantCode(t, err, ErrFormat)
			if source.read > MaxSize+1 {
				t.Fatalf("read %d bytes, want at most %d", source.read, MaxSize+1)
			}
		})
		t.Run("a reader of 65,537 bytes", func(t *testing.T) {
			t.Parallel()
			_, err := readFile(&countingReader{size: MaxSize + 1})
			wantCode(t, err, ErrFormat)
		})
		t.Run("a reader of 65,536 bytes is read whole", func(t *testing.T) {
			t.Parallel()
			file, err := readFile(&countingReader{size: MaxSize})
			if err != nil {
				t.Fatalf("got %v, want the file", err)
			}
			if len(file) != MaxSize {
				t.Fatalf("got %d bytes, want %d", len(file), MaxSize)
			}
		})
	})
}

// countingReader gives size zero bytes, or never ends when size is negative, and counts every
// byte read from it.
type countingReader struct {
	size int
	read int
}

func (source *countingReader) Read(buffer []byte) (int, error) {
	if source.size >= 0 && source.read >= source.size {
		return 0, io.EOF
	}
	count := len(buffer)
	if source.size >= 0 {
		count = min(count, source.size-source.read)
	}
	clear(buffer[:count])
	source.read += count
	return count, nil
}

// placeRows are the rows on a missing or unreadable folder or file that need no key holder,
// no oracle and no link, the same on Windows and Linux.
func placeRows(t *testing.T) {
	t.Helper()
	t.Run(lineNotFound, func(t *testing.T) {
		t.Parallel()
		t.Run(rowFolderMissing, func(t *testing.T) {
			t.Parallel()
			file, err := open(t, filepath.Join(t.TempDir(), "missing"))
			wantRefused(t, file, err, ErrNotFound)
		})
		t.Run(rowFileMissing, func(t *testing.T) {
			t.Parallel()
			file, err := open(t, t.TempDir())
			wantRefused(t, file, err, ErrNotFound)
		})
	})
	t.Run(lineFolderUnreadable, func(t *testing.T) {
		t.Parallel()
		t.Run(rowFileForFolder, func(t *testing.T) {
			t.Parallel()
			file, err := open(t, fileForFolder(t))
			wantRefused(t, file, err, ErrUnreadable)
			wantCause(t, err)
		})
	})
	t.Run(lineFileUnreadable, func(t *testing.T) {
		t.Parallel()
		t.Run(rowFolderForFile, func(t *testing.T) {
			t.Parallel()
			file, err := open(t, folderForFile(t))
			wantRefused(t, file, err, ErrUnreadable)
			wantCause(t, err)
		})
	})
	t.Run(linePlace, func(t *testing.T) {
		t.Parallel()
		for _, row := range []struct {
			name   string
			folder func(t *testing.T) string
			code   error
			place  Place
		}{
			{rowFolderMissing, func(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "missing") }, ErrNotFound, PlaceFolder},
			{rowFileMissing, func(t *testing.T) string { t.Helper(); return t.TempDir() }, ErrNotFound, PlaceFile},
			{rowFileForFolder, fileForFolder, ErrUnreadable, PlaceFolder},
			{rowFolderForFile, folderForFile, ErrUnreadable, PlaceFile},
		} {
			t.Run(row.name, func(t *testing.T) {
				t.Parallel()
				file, err := open(t, row.folder(t))
				wantRefused(t, file, err, row.code)
				wantPlace(t, err, row.place)
			})
		}
	})
}

// fileForFolder is a path that holds a file, given as the bootstrap folder.
func fileForFolder(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "folder")
	if err := os.WriteFile(path, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// folderForFile is a bootstrap folder in which bootstrap.hadv is a folder.
func folderForFile(t *testing.T) string {
	t.Helper()
	folder := t.TempDir()
	if err := os.Mkdir(filepath.Join(folder, FileName), 0o700); err != nil {
		t.Fatal(err)
	}
	return folder
}

// open opens the bootstrap file in folder, as both programs do.
func open(t *testing.T, folder string) (File, error) {
	t.Helper()
	return New().Open(t.Context(), folder, rowAccount)
}

// wantCode fails unless err carries code, as an Error.
func wantCode(t *testing.T, err, code error) {
	t.Helper()
	if !errors.Is(err, code) {
		t.Fatalf("got %v, want %v", err, code)
	}
	var failure Error
	if !errors.As(err, &failure) {
		t.Fatalf("got %T, want an Error", err)
	}
}

// wantRefused fails unless open gave no handle and err carries code.
func wantRefused(t *testing.T, file File, err, code error) {
	t.Helper()
	if file != nil {
		file.Release()
		t.Error("got a handle, want none")
	}
	wantCode(t, err, code)
}

// wantCause fails unless the OS's own error is beneath err.
func wantCause(t *testing.T, err error) {
	t.Helper()
	var failure Error
	if !errors.As(err, &failure) || failure.Err == nil {
		t.Fatalf("got %v, want the OS's cause beneath it", err)
	}
	var osError *fs.PathError
	if !errors.As(failure.Err, &osError) {
		t.Fatalf("the cause beneath is %T (%v), want the OS's own error", failure.Err, failure.Err)
	}
}

// wantPlace fails unless err names place as its cause.
func wantPlace(t *testing.T, err error, place Place) {
	t.Helper()
	var failure Error
	if !errors.As(err, &failure) {
		t.Fatalf("got %T, want an Error", err)
	}
	if failure.Place != place {
		t.Fatalf("got the place %d, want %d", failure.Place, place)
	}
}

// recordList is a record list in the oracle's form, one directive a line.
type recordList []string

func listOf(text string) recordList {
	var list recordList
	for line := range strings.SplitSeq(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			list = append(list, line)
		}
	}
	return list
}

// records is each record line of list as a record, name and data, in order.
func (list recordList) records() ([]record, error) {
	var records []record
	for _, line := range list {
		rest, found := strings.CutPrefix(line, "record ")
		if !found {
			continue
		}
		name, rest, err := valueOf(rest)
		if err != nil {
			return nil, err
		}
		data, rest, err := valueOf(strings.TrimLeft(rest, " "))
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(rest) != "" {
			return nil, errors.New("a record line with more than a name and data: " + line)
		}
		records = append(records, record{name: string(name), data: data})
	}
	return records, nil
}

// valueOf reads one NAME or DATA value of a record list from the start of text, in the forms
// the kept samples and the rows use: "text", hex:, and zeros:.
func valueOf(text string) ([]byte, string, error) {
	switch {
	case strings.HasPrefix(text, `"`):
		var value []byte
		for i := 1; i < len(text); i++ {
			switch text[i] {
			case '"':
				return value, text[i+1:], nil
			case '\\':
				if i+1 >= len(text) {
					return nil, "", errors.New("a value ends inside an escape")
				}
				i++
				switch text[i] {
				case 'n':
					value = append(value, '\n')
				case 'r':
					value = append(value, '\r')
				case 't':
					value = append(value, '\t')
				case 'x':
					if i+2 >= len(text) {
						return nil, "", errors.New("a value ends inside an escape")
					}
					decoded, err := hex.DecodeString(text[i+1 : i+3])
					if err != nil {
						return nil, "", err
					}
					value = append(value, decoded...)
					i += 2
				default:
					value = append(value, text[i])
				}
			default:
				value = append(value, text[i])
			}
		}
		return nil, "", errors.New("a value with no closing quote")
	case strings.HasPrefix(text, "hex:"), strings.HasPrefix(text, "zeros:"):
		token, rest, _ := strings.Cut(text, " ")
		if digits, found := strings.CutPrefix(token, "hex:"); found {
			value, err := hex.DecodeString(digits)
			return value, rest, err
		}
		count, err := strconv.Atoi(strings.TrimPrefix(token, "zeros:"))
		if err != nil || count < 0 {
			return nil, "", errors.New("a zeros: value that is not a count: " + token)
		}
		return make([]byte, count), rest, nil
	}
	return nil, "", errors.New("a value in a form the rows do not use: " + text)
}

// plaintextOf frames records as the format gives them: each name's length in 2 bytes, the name,
// the data's length in 4 bytes, the data.
func plaintextOf(records []record) ([]byte, error) {
	var plaintext []byte
	for _, rec := range records {
		if len(rec.name) > 0xFFFF || len(rec.data) > 0xFFFFFFFF {
			return nil, errors.New("a record too long to frame")
		}
		plaintext = append(plaintext, bigEndian(len(rec.name), 2)...)
		plaintext = append(plaintext, rec.name...)
		plaintext = append(plaintext, bigEndian(len(rec.data), 4)...)
		plaintext = append(plaintext, rec.data...)
	}
	return plaintext, nil
}

// bigEndian is length in size bytes, big-endian, for a length plaintextOf has checked fits.
func bigEndian(length, size int) []byte {
	return big.NewInt(int64(length)).FillBytes(make([]byte, size))
}
