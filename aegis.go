// Package aegis implements the AEGIS AEAD algorithm.
//
//    [aegis]: https://www.ietf.org/archive/id/draft-denis-aegis-aead-00.html
//
package aegis

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"runtime"

	"github.com/ericlagergren/subtle"
)

var errOpen = errors.New("aegis: message authentication failure")

const (
	// KeySize128L is the size in bytes of an AEGIS-128L key.
	KeySize128L = 16
	// NonceSize128L is the size in bytes of an AEGIS-128L nonce.
	NonceSize128L = 16
	// TagSize128L is the size in bytes of an AEGIS-128L
	// authentication tag.
	TagSize128L = 16
	// BlockSize128L is the size in bytes of an AEGIS-128L block.
	BlockSize128L = 32

	// MaxPlaintextSize128L is the size in bytes of the largest
	// allowed AESGIS-128L plaintext.
	MaxPlaintextSize128L = 1 << 61
	// MaxAdditionalDataSize128L is the size in bytes of the
	// largest allowed AEGIS-128L additional data.
	MaxAdditionalDataSize128L = 1 << 61
	// ciphertextMax128L is the size in bytes of the largest
	// allowed AESGIS-128L ciphertext.
	ciphertextMax128L = MaxPlaintextSize128L + TagSize128L

	// KeySize256 is the size in bytes of an AEGIS-256 key.
	KeySize256 = 32
	// NonceSize256 is the size in bytes of an AEGIS-256 nonce.
	NonceSize256 = 32
	// TagSize256 is the size in bytes of an AEGIS-256
	// authentication tag.
	TagSize256 = 16
	// BlockSize256 is the size in bytes of an AEGIS-256 block.
	BlockSize256 = 16

	// MaxPlaintextSize256 is the size in bytes of the largest
	// allowed AESGIS-256 plaintext.
	MaxPlaintextSize256 = 1 << 61
	// MaxAdditionalDataSize256 is the size in bytes of the
	// largest allowed AEGIS-256 additional data.
	MaxAdditionalDataSize256 = 1 << 61
	// ciphertextMax256 is the size in bytes of the largest
	// allowed AESGIS-256 ciphertext.
	ciphertextMax256 = MaxPlaintextSize256 + TagSize256
)

// New creates an instance of the AEGIS AEAD algorithm.
//
// New accepts two key lengths. If the key is 128 bits, New
// returns an instance of AEGIS-128L. Otherwise, if the key is
// 256 bits, New returns an instance of AEGIS-256. Any other key
// lengths are an error.
func New(key []byte) (cipher.AEAD, error) {
	switch len(key) {
	case KeySize128L:
		return &aegis128{key: *(*[KeySize128L]byte)(key)}, nil
	case KeySize256:
		return &aegis256{key: *(*[KeySize256]byte)(key)}, nil
	default:
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}
}

type aegis128 struct {
	key [KeySize128L]byte
}

func (*aegis128) NonceSize() int {
	return NonceSize128L
}

func (*aegis128) Overhead() int {
	return TagSize128L
}

func (a *aegis128) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if uint64(len(plaintext)) > MaxPlaintextSize128L {
		panic("aegis: plaintext too large")
	}
	if len(nonce) != NonceSize128L {
		panic("aegis: invalid nonce length")
	}
	if uint64(len(additionalData)) > MaxAdditionalDataSize128L {
		panic("aegis: additional data too large")
	}

	ret, out := subtle.SliceForAppend(dst, len(plaintext)+TagSize128L)
	if subtle.InexactOverlap(out, plaintext) {
		panic("aegis: invalid buffer overlap")
	}
	seal128L(&a.key, (*[NonceSize128L]byte)(nonce),
		out, plaintext, additionalData)
	return ret
}

func (a *aegis128) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize128L {
		panic("aegis: invalid nonce length")
	}
	if len(ciphertext) < TagSize128L ||
		uint64(len(ciphertext)) > ciphertextMax128L ||
		uint64(len(additionalData)) > MaxAdditionalDataSize128L {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-TagSize128L:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize128L]

	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("aegis: invalid buffer overlap")
	}

	ok := open128L(&a.key, (*[NonceSize128L]byte)(nonce), out,
		ciphertext, tag, additionalData)
	if !ok {
		memclr(out)
		return nil, errOpen
	}
	return ret, nil
}

type aegis256 struct {
	key [KeySize256]byte
}

func (*aegis256) NonceSize() int {
	return NonceSize256
}

func (*aegis256) Overhead() int {
	return TagSize256
}

func (a *aegis256) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if uint64(len(plaintext)) > MaxPlaintextSize256 {
		panic("aegis: plaintext too large")
	}
	if len(nonce) != NonceSize256 {
		panic("aegis: invalid nonce length")
	}
	if uint64(len(additionalData)) > MaxAdditionalDataSize256 {
		panic("aegis: additional data too large")
	}

	ret, out := subtle.SliceForAppend(dst, len(plaintext)+TagSize256)
	if subtle.InexactOverlap(out, plaintext) {
		panic("aegis: invalid buffer overlap")
	}

	seal256(&a.key, (*[NonceSize256]byte)(nonce), out, plaintext, additionalData)
	return ret
}

func (a *aegis256) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize256 {
		panic("aegis: invalid nonce length")
	}
	if len(ciphertext) < TagSize256 ||
		uint64(len(ciphertext)) > ciphertextMax256 ||
		uint64(len(additionalData)) > MaxAdditionalDataSize256 {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-TagSize256:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize256]

	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("aegis: invalid buffer overlap")
	}

	ok := open256(&a.key, (*[NonceSize256]byte)(nonce), out,
		ciphertext, tag, additionalData)
	if !ok {
		memclr(out)
		return nil, errOpen
	}
	return ret, nil
}

//go:noinline
func memclr(p []byte) {
	for i := range p {
		p[i] = 0
	}
	runtime.KeepAlive(p)
}
