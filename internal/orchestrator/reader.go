package orchestrator

import (
	"io"
	"strings"
)

// maxIntentBytes bounds how much model-proposed JSON the broker will decode.
const maxIntentBytes = 16384

func newLimitedReader(s string) io.Reader {
	return io.LimitReader(strings.NewReader(s), maxIntentBytes)
}
