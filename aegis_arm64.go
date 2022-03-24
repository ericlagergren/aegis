//go:build arm64 && gc && !purego

package aegis

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

var haveSHA3 = runtime.GOOS == "darwin" || cpu.ARM64.HasSHA3

func seal128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, plaintext, additionalData []byte) {
	if haveAsm {
		if haveSHA3 {
			seal128LAsmSHA3(key, nonce, out, plaintext, additionalData)
		} else {
			seal128LAsm(key, nonce, out, plaintext, additionalData)
		}
	} else {
		seal128LGeneric(key, nonce, out, plaintext, additionalData)
	}
}

func open128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, ciphertext, tag, additionalData []byte) bool {
	if haveAsm {
		if haveSHA3 {
			return open128LAsmSHA3(key, nonce, out, ciphertext, tag, additionalData)
		}
		return open128LAsm(key, nonce, out, ciphertext, tag, additionalData)
	}
	return open128LGeneric(key, nonce, out, ciphertext, tag, additionalData)
}

func seal256(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, plaintext, additionalData []byte) {
	if haveAsm {
		if haveSHA3 {
			seal256AsmSHA3(key, nonce, out, plaintext, additionalData)
		} else {
			seal256Asm(key, nonce, out, plaintext, additionalData)
		}
	} else {
		seal256Generic(key, nonce, out, plaintext, additionalData)
	}
}

func open256(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, ciphertext, tag, additionalData []byte) bool {
	if haveAsm {
		if haveSHA3 {
			return open256AsmSHA3(key, nonce, out, ciphertext, tag, additionalData)
		}
		return open256Asm(key, nonce, out, ciphertext, tag, additionalData)
	}
	return open256Generic(key, nonce, out, ciphertext, tag, additionalData)
}
