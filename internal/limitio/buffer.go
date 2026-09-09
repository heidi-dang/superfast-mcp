package limitio

import "bytes"

// Buffer is an io.Writer that retains at most limit bytes while reporting all
// input bytes as consumed. This keeps child-process output from growing memory
// without bound.
type Buffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func NewBuffer(limit int) *Buffer {
	if limit < 0 {
		limit = 0
	}
	return &Buffer{limit: limit}
}

func (b *Buffer) Write(p []byte) (int, error) {
	consumed := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return consumed, nil
}

func (b *Buffer) String() string {
	if !b.truncated {
		return b.buf.String()
	}
	return b.buf.String() + "\n...[truncated]"
}

func (b *Buffer) Truncated() bool {
	return b.truncated
}
