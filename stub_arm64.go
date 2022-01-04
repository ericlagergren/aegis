//go:build gc && !purego

package aegis

//go:noescape
func seal128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, plaintext, additionalData []byte)

//go:noescape
func open128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, expectedTag *[TagSize128L]byte, out, ciphertext, additionalData []byte)

//go:noescape
func update128L(s *state128L, m *[BlockSize128L]byte)

//go:noescape
func seal256(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, plaintext, additionalData []byte)

//go:noescape
func open256(key *[KeySize256]byte, nonce *[NonceSize256]byte, expectedTag *[TagSize256]byte, out, ciphertext, additionalData []byte)

//go:noescape
func update256(s *state256, m *[BlockSize256]byte)

//go:noescape
func aesRound(out, in, rk *[16]byte)

//go:noescape
func copy32(dst, src []byte)
