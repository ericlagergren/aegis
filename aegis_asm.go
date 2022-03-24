//go:build (amd64 || arm64) && gc && !purego

package aegis

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

var (
	haveAsm = runtime.GOOS == "darwin" ||
		cpu.ARM64.HasAES ||
		(cpu.ARM.HasAES && cpu.ARM.HasNEON) ||
		(cpu.X86.HasAES && cpu.X86.HasSSE41)
)

func update128L(s *state128L, m *[BlockSize128L]byte) {
	if haveAsm {
		update128LAsm(s, m)
	} else {
		update128LGeneric(s, readUint128(m[0:16]), readUint128(m[16:32]))
	}
}

func update256(s *state256, m *[BlockSize256]byte) {
	if haveAsm {
		update256Asm(s, m)
	} else {
		update256Generic(s, readUint128(m[0:16]))
	}
}

func aesRound(out, in, rk *[16]byte) {
	if haveAsm {
		aesRoundAsm(out, in, rk)
	} else {
		r := aesRoundGeneric(readUint128(in[:]), readUint128(rk[:]))
		putUint128(out[:], r)
	}
}
