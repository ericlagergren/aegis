//go:build amd64 && gc && !purego

package aegis

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
