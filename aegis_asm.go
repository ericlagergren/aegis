//go:build (arm64 || amd64) && gc && !purego

package aegis

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

var haveAsm = runtime.GOOS == "darwin" ||
	cpu.ARM64.HasAES ||
	(cpu.X86.HasAES && cpu.X86.HasSSE41)

func seal128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, plaintext, additionalData []byte) {
	if haveAsm {
		seal128LAsm(key, nonce, out, plaintext, additionalData)
	} else {
		seal128LGeneric(key, nonce, out, plaintext, additionalData)
	}
}

func open128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, ciphertext, tag, additionalData []byte) bool {
	if haveAsm {
		return open128LAsm(key, nonce, out, ciphertext, tag, additionalData)
	}
	return open128LGeneric(key, nonce, out, ciphertext, tag, additionalData)
}

func update128L(s *state128L, m *[BlockSize128L]byte) {
	if haveAsm {
		update128LAsm(s, m)
	} else {
		update128LGeneric(s, readUint128(m[0:16]), readUint128(m[16:32]))
	}
}

func seal256(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, plaintext, additionalData []byte) {
	if haveAsm {
		seal256Asm(key, nonce, out, plaintext, additionalData)
	} else {
		seal256Generic(key, nonce, out, plaintext, additionalData)
	}
}

func open256(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, ciphertext, tag, additionalData []byte) bool {
	if haveAsm {
		return open256Asm(key, nonce, out, ciphertext, tag, additionalData)
	}
	return open256Generic(key, nonce, out, ciphertext, tag, additionalData)
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
