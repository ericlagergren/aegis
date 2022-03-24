//go:build gc && !purego

package aegis

//go:noescape
func seal128LAsm(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, plaintext, additionalData []byte)

//go:noescape
func seal128LAsmSHA3(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, plaintext, additionalData []byte)

//go:noescape
func open128LAsm(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, ciphertext, tag, additionalData []byte) (ok bool)

//go:noescape
func open128LAsmSHA3(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, ciphertext, tag, additionalData []byte) (ok bool)

//go:noescape
func update128LAsm(s *state128L, m *[BlockSize128L]byte)

//go:noescape
func seal256Asm(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, plaintext, additionalData []byte)

//go:noescape
func seal256AsmSHA3(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, plaintext, additionalData []byte)

//go:noescape
func open256Asm(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, ciphertext, tag, additionalData []byte) (ok bool)

//go:noescape
func open256AsmSHA3(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, ciphertext, tag, additionalData []byte) (ok bool)

//go:noescape
func update256Asm(s *state256, m *[BlockSize256]byte)

//go:noescape
func aesRoundAsm(out, in, rk *[16]byte)

//go:noescape
func copy32(dst, src []byte)
