package limitio

import (
	"strings"
	"testing"
)

func TestBufferBoundsRetainedOutput(t *testing.T) {
	buf := NewBuffer(5)
	input := []byte("abcdefgh")
	n, err := buf.Write(input)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(input) {
		t.Fatalf("Write consumed %d bytes, want %d", n, len(input))
	}
	if got := buf.String(); got != "abcde\n...[truncated]" {
		t.Fatalf("String() = %q", got)
	}
	if !buf.Truncated() {
		t.Fatal("expected truncation")
	}
	if strings.Count(buf.String(), "truncated") != 1 {
		t.Fatal("truncation marker should be stable")
	}
}
