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

func BenchmarkSeal16B_128LNoSHA3(b *testing.B) {
	benchmarkSealNoSHA3(b, KeySize128L, NonceSize128L, make([]byte, 16))
}

func BenchmarkOpen16B_128LNoSHA3(b *testing.B) {
	benchmarkOpenNoSHA3(b, KeySize128L, NonceSize128L, make([]byte, 16))
}

func BenchmarkSeal1K_128LNoSHA3(b *testing.B) {
	benchmarkSealNoSHA3(b, KeySize128L, NonceSize128L, make([]byte, 1024))
}

func BenchmarkOpen1K_128LNoSHA3(b *testing.B) {
	benchmarkOpenNoSHA3(b, KeySize128L, NonceSize128L, make([]byte, 1024))
}

func BenchmarkSeal8K_128LNoSHA3(b *testing.B) {
	benchmarkSealNoSHA3(b, KeySize128L, NonceSize128L, make([]byte, 8*1024))
}

func BenchmarkOpen8K_128LNoSHA3(b *testing.B) {
	benchmarkOpenNoSHA3(b, KeySize128L, NonceSize128L, make([]byte, 8*1024))
}

func BenchmarkSeal16B_256NoSHA3(b *testing.B) {
	benchmarkSealNoSHA3(b, KeySize256, NonceSize256, make([]byte, 16))
}

func BenchmarkOpen16B_256NoSHA3(b *testing.B) {
	benchmarkOpenNoSHA3(b, KeySize256, NonceSize256, make([]byte, 16))
}

func BenchmarkSeal1K_256NoSHA3(b *testing.B) {
	benchmarkSealNoSHA3(b, KeySize256, NonceSize256, make([]byte, 1024))
}

func BenchmarkOpen1K_256NoSHA3(b *testing.B) {
	benchmarkOpenNoSHA3(b, KeySize256, NonceSize256, make([]byte, 1024))
}

func BenchmarkSeal8K_256NoSHA3(b *testing.B) {
	benchmarkSealNoSHA3(b, KeySize256, NonceSize256, make([]byte, 8*1024))
}

func BenchmarkOpen8K_256NoSHA3(b *testing.B) {
	benchmarkOpenNoSHA3(b, KeySize256, NonceSize256, make([]byte, 8*1024))
}

func benchmarkSealNoSHA3(b *testing.B, keySize, nonceSize int, buf []byte) {
	if !haveSHA3 {
		b.Skip("CPU does not support SHA-3 extensions")
	}
	haveSHA3 = false
	b.Cleanup(func() {
		haveSHA3 = true
	})
	benchmarkSeal(b, keySize, nonceSize, buf)
}

func benchmarkOpenNoSHA3(b *testing.B, keySize, nonceSize int, buf []byte) {
	if !haveSHA3 {
		b.Skip("CPU does not support SHA-3 extensions")
	}
	benchmarkOpen(b, keySize, nonceSize, buf)
}
