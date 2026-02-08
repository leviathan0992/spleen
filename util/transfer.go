package util

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sync"
)

/* Buffer size (32KB) for TCP data transfer. */
const TransferBuf = 32 * 1024

/* Byte buffer pool to reduce memory allocation overhead. */
var bytePool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, TransferBuf)
		return &buf
	},
}

/* Transfers data between two streams using buffered IO. */
func Transfer(src io.Reader, dst io.Writer) error {
	_, err := TransferCount(src, dst)
	return err
}

/* TransferCount copies bytes and returns copied size. */
func TransferCount(src io.Reader, dst io.Writer) (int64, error) {
	bufPtr := bytePool.Get().(*[]byte)
	defer bytePool.Put(bufPtr)

	n, err := io.CopyBuffer(dst, src, *bufPtr)
	return n, err
}

/* ReadLineLimited reads a newline-terminated frame with a strict size limit. */
func ReadLineLimited(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 4096
	}

	out := make([]byte, 0, 256)
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(out)+len(chunk) > maxBytes {
			return nil, fmt.Errorf("frame too large")
		}
		out = append(out, chunk...)

		if err == nil {
			return out, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
}
