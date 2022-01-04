//go:build !(arm64 && gc) || purego

package aegis

func seal128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, plaintext, additionalData []byte) {
	seal128LGeneric(key, nonce, out, plaintext, additionalData)
}

func open128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, expectedTag *[TagSize128L]byte, out, ciphertext, additionalData []byte) {
	open128LGeneric(key, nonce, expectedTag, out, ciphertext, additionalData)
}

func update128L(s *state128L, m *[BlockSize128L]byte) {
	update128LGeneric(s, readUint128(m[0:16]), readUint128(m[16:32]))
}

func seal256(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, plaintext, additionalData []byte) {
	seal256Generic(key, nonce, out, plaintext, additionalData)
}

func open256(key *[KeySize256]byte, nonce *[NonceSize256]byte, expectedTag *[TagSize128L]byte, out, ciphertext, additionalData []byte) {
	open256Generic(key, nonce, expectedTag, out, ciphertext, additionalData)
}

func update256(s *state256, m *[BlockSize256]byte) {
	update256Generic(s, readUint128(m[:]))
}

func aesRound(out, in, rk *[16]byte) {
	r := aesRoundGeneric(readUint128(in[:]), readUint128(rk[:]))
	putUint128(out[:], r)
}
