//go:build arm64 && gc && !purego

package aegis

import (
	"os"
	"testing"
)

func TestCopy32(t *testing.T) {
	dst := make([]byte, os.Getpagesize())
	src := make([]byte, 32)
	for i := range src {
		src[i] = byte(i)
	}
	for i := 0; i < len(dst); i++ {
		for j := 0; j < len(src); j++ {
			end := i + j
			if end > len(dst) {
				end = len(dst)
			}
			dst := dst[i:end]
			for k := range dst {
				dst[k] = 0
			}
			copy32(dst, src[:j])
			for k, c := range dst {
				if c != byte(k) {
					t.Fatalf("%d: bad value at index %d: %d", i, k, c)
				}
			}
		}
	}
}
