// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// What Load reads, from the system's own count of the bytes this process has read: no more than
// MostFileBytes and one byte of a file over it, and each file once. The count is the whole
// process's, so these rows run alone: no other row reads beside them.
package language_test

import (
	"os"
	"path/filepath"
	"testing"
)

// readBy runs load and returns how many bytes this process read while it ran. The count's own
// reading is taken out: the bytes the reading before load read, which the system counts after it.
// A first pair of readings with nothing between proves that is all a reading adds.
func readBy(t *testing.T, load func()) int64 {
	t.Helper()
	first, firstLength := bytesRead(t)
	second, secondLength := bytesRead(t)
	if second-first != firstLength {
		t.Fatalf("two readings of the count with nothing between differ by %d, not the %d bytes the first read: a fault in the test", second-first, firstLength)
	}
	load()
	after, _ := bytesRead(t)
	return after - second - secondLength
}

// sizeOf is a file's size on disk.
func sizeOf(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("reading %s's size: %v", path, err)
	}
	return info.Size()
}

func TestLinuxReadBound(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads, so no other row may run beside it
	t.Run("If a language's file is over MostFileBytes, then Load shall return ErrFileRefused naming it, having read no more than MostFileBytes and one byte of it.", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
		for name, size := range map[string]int{"2 MiB": 2 << 20, "64 MiB": 64 << 20} {
			t.Run("fr-fr a valid file padded to "+name+": ErrFileRefused, no more read than en-us and 1 MiB and one byte", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
				folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: padded(t, frFile(nil), size)})
				most := sizeOf(t, filepath.Join(folder, fallbackCode, fileName(fallbackCode))) + mostFileBytes + 1
				read := readBy(t, func() { expectRefused(t, folder, fallbackCode, fileName(frFR)) })
				if read > most {
					t.Fatalf("Load read %d bytes, more than %d", read, most)
				}
			})
		}
	})
	t.Run("Load shall read each language's file once, and every language's, not only those in the chain.", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
		t.Run("fr-fr a valid file of 900 KiB, the board en-us: exactly the two files' sizes read", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
			folder := makeLang(t, map[string]string{fallbackCode: enUSFile(), frFR: padded(t, frFile(nil), 900<<10)})
			want := sizeOf(t, filepath.Join(folder, fallbackCode, fileName(fallbackCode))) + sizeOf(t, filepath.Join(folder, frFR, fileName(frFR)))
			read := readBy(t, func() { expectShown(t, expectLoaded(t, folder, fallbackCode), enUSShown) })
			if read != want {
				t.Fatalf("Load read %d bytes, not the %d the two files hold", read, want)
			}
		})
		t.Run("es-mx, es-es and en-us, the board es-mx: exactly the three files' sizes read", func(t *testing.T) { //nolint:paralleltest // it counts every byte this process reads
			folder := makeLang(t, map[string]string{
				fallbackCode: enUSFile(),
				esES:         padded(t, esFile(esES, "", esTexts(esES)), 300<<10),
				esMX:         padded(t, esFile(esMX, esES, esTexts(esMX, shortGreeting)), 200<<10),
			})
			var want int64
			for _, code := range []string{fallbackCode, esES, esMX} {
				want += sizeOf(t, filepath.Join(folder, code, fileName(code)))
			}
			read := readBy(t, func() {
				expectShown(t, expectLoaded(t, folder, esMX), esShown(esMX).from(keyGreeting, esShown(esES)).missingFrom(keyGreeting))
			})
			if read != want {
				t.Fatalf("Load read %d bytes, not the %d the three files hold", read, want)
			}
		})
	})
}
