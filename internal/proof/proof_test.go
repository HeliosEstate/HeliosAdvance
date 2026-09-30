package proof

import (
	"os"
	"testing"
)

// Deliberate violation: a TestMain in a test file that no QA commit approved.
func TestMain(m *testing.M) { os.Exit(m.Run()) }

func TestPort(t *testing.T) {
	if Port() != 0 {
		t.Fatal("expected 0")
	}
}
