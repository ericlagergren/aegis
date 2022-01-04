// Package ref implements a wrapper around the reference
// implementation of AEGIS.
//
// Version used: https://github.com/jedisct1/supercop/tree/88bd06ad510071816430e393ea571ad7a14d60e8/crypto_aead/aegis128l
package ref

/*
#include "crypto_aead.h"
*/
import "C"

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/ericlagergren/aegis/internal/subtle"
)

const (
	aegis128l = iota
	aegis256
)

type aead struct {
	key       []byte
	nonceSize int
	overhead  int
	impl      int
}

func New(key []byte) (cipher.AEAD, error) {
	switch len(key) {
	case 16:
		return &aead{
			key:       key,
			nonceSize: 16,
			overhead:  16,
			impl:      aegis128l,
		}, nil
	case 32:
		return &aead{
			key:       key,
			nonceSize: 32,
			overhead:  16,
			impl:      aegis256,
		}, nil
	default:
		return nil, fmt.Errorf("invalid key size: %d", len(key))
	}
}

func (a *aead) NonceSize() int {
	return a.nonceSize
}

func (a *aead) Overhead() int {
	return a.overhead
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != a.NonceSize() {
		panic("aegis: invalid nonce length")
	}
	ret, out := subtle.SliceForAppend(dst, len(plaintext)+a.Overhead())
	if subtle.InexactOverlap(out, plaintext) {
		panic("aegis: invalid buffer overlap")
	}
	var m *C.uchar
	if len(plaintext) > 0 {
		m = (*C.uchar)(&plaintext[0])
	}
	var ad *C.uchar
	if len(additionalData) > 0 {
		ad = (*C.uchar)(&additionalData[0])
	}
	clen := C.ulonglong(len(out))
	var r C.int
	switch a.impl {
	case aegis128l:
		r = C.crypto_aead_encrypt_128l(
			(*C.uchar)(&out[0]),
			&clen,
			m,
			C.ulonglong(len(plaintext)),
			ad,
			C.ulonglong(len(additionalData)),
			nil,
			(*C.uchar)(&nonce[0]),
			(*C.uchar)(&a.key[0]),
		)
	case aegis256:
		r = C.crypto_aead_encrypt_256(
			(*C.uchar)(&out[0]),
			&clen,
			m,
			C.ulonglong(len(plaintext)),
			ad,
			C.ulonglong(len(additionalData)),
			nil,
			(*C.uchar)(&nonce[0]),
			(*C.uchar)(&a.key[0]),
		)
	}
	if r != 0 {
		panic("crypto_aead_encrypt")
	}
	return ret
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		panic("aegis: invalid nonce length")
	}
	if len(ciphertext) < a.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	ret, out := subtle.SliceForAppend(dst, len(ciphertext)-a.Overhead())
	if subtle.InexactOverlap(out, ciphertext) {
		panic("aegis: invalid buffer overlap")
	}
	var ad *C.uchar
	if len(additionalData) > 0 {
		ad = (*C.uchar)(&additionalData[0])
	}
	var _out *C.uchar
	if len(out) > 0 {
		_out = (*C.uchar)(&out[0])
	}
	mlen := C.ulonglong(len(out))
	var r C.int
	switch a.impl {
	case aegis128l:
		r = C.crypto_aead_decrypt_128l(
			_out,
			&mlen,
			nil,
			(*C.uchar)(&ciphertext[0]),
			C.ulonglong(len(ciphertext)),
			ad,
			C.ulonglong(len(additionalData)),
			(*C.uchar)(&nonce[0]),
			(*C.uchar)(&a.key[0]),
		)
	case aegis256:
		r = C.crypto_aead_decrypt_256(
			_out,
			&mlen,
			nil,
			(*C.uchar)(&ciphertext[0]),
			C.ulonglong(len(ciphertext)),
			ad,
			C.ulonglong(len(additionalData)),
			(*C.uchar)(&nonce[0]),
			(*C.uchar)(&a.key[0]),
		)
	}
	if r != 0 {
		for i := range out {
			out[i] = 0
		}
		return nil, errors.New("auth failed")
	}
	return ret, nil
}
