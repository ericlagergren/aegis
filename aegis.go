// Package aegis implements the AEGIS AEAD algorithm.
//
//    [aegis]: https://www.ietf.org/archive/id/draft-denis-aegis-aead-00.html
//
package aegis

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"runtime"

	"github.com/ericlagergren/aegis/internal/subtle"
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

	// plaintextMax128L is the size in bytes of the largest
	// allowed AESGIS-128L plaintext.
	plaintextMax128L = 1 << 61
	// ciphertextMax128L is the size in bytes of the largest
	// allowed AESGIS-128L ciphertext.
	ciphertextMax128L = plaintextMax128L + 16
	// adMax128L is the size in bytes of the largest allowed
	// AEGIS-128L additional data.
	adMax128L = 1 << 61
)

// New creates an instance of the AEGIS AEAD algorithm.
//
// New accepts two key lengths. If the key is 128 bits, New
// returns an instance of AEGIS-128L. If the key is 256 bits, New
// returns an instance of AEGIS-256. Any other key lengths are an
// error.
func New(key []byte) (cipher.AEAD, error) {
	switch len(key) {
	case KeySize128L:
		return new128L(key), nil
	// case 32:
	// 	panic("TODO")
	default:
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}
}

type aegis128 struct {
	key uint128
}

func new128L(key []byte) *aegis128 {
	return &aegis128{
		key: uint128{
			hi: binary.BigEndian.Uint64(key[0:8]),
			lo: binary.BigEndian.Uint64(key[8:16]),
		},
	}
}

func (*aegis128) NonceSize() int {
	return NonceSize128L
}

func (*aegis128) Overhead() int {
	return TagSize128L
}

func (a *aegis128) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(plaintext) > plaintextMax128L {
		panic("aegis: plaintext too large")
	}
	if len(nonce) != NonceSize128L {
		panic("aegis: invalid nonce length")
	}
	if len(additionalData) > adMax128L {
		panic("aegis: additional data too large")
	}

	ret, out := subtle.SliceForAppend(dst, len(plaintext)+TagSize128L)
	if subtle.InexactOverlap(out, plaintext) {
		panic("aegis: invalid buffer overlap")
	}

	var s [8]uint128

	// Init(key, nonce)
	init128L(&s, a.key, readUint128(nonce))

	// ad_blocks = Split(Pad(ad, 256), 256)
	// for xi in ad_blocks:
	//     Enc(xi)
	authBlocks128L(&s, additionalData)

	// msg_blocks = Split(Pad(msg, 256), 256)
	// for xi in msg_blocks:
	//     ct = ct || Enc(xi)
	encryptBlocks128L(&s, out[:len(plaintext)], plaintext)

	// tag = Finalize(|ad|, |msg|)
	finalize128L(&s, out[len(out)-TagSize128L:],
		len(additionalData)*8, len(plaintext)*8)

	return ret
}

func (a *aegis128) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize128L {
		panic("aegis: invalid nonce length")
	}
	if len(ciphertext) < TagSize128L ||
		len(ciphertext) > ciphertextMax128L ||
		len(additionalData) > adMax128L {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-TagSize128L:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize128L]

	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("aegis: invalid buffer overlap")
	}

	var s [8]uint128

	// Init(key, nonce)
	init128L(&s, a.key, readUint128(nonce))

	// ad_blocks = Split(Pad(ad, 256), 256)
	// for xi in ad_blocks:
	//     Enc(xi)
	authBlocks128L(&s, additionalData)

	// ct_blocks = Split(ct, 256)
	// cn = Tail(ct, |ct| mod 256)
	//
	// for ci in ct_blocks:
	//     msg = msg || Dec(ci)
	// if cn is not empty:
	//     msg = msg || DecPartial(cn)
	decryptBlocks128L(&s, out, ciphertext)

	// expected_tag = Finalize(|ad|, |msg|)
	expectedTag := make([]byte, TagSize128L)
	finalize128L(&s, expectedTag, len(additionalData)*8, len(out)*8)

	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		runtime.KeepAlive(out)
		return nil, errOpen
	}
	return ret, nil
}

func init128L(s *[8]uint128, key, nonce uint128) {
	C0 := uint128{0x000101020305080d, 0x1522375990e97962}
	C1 := uint128{0xdb3d18556dc22ff1, 0x2011314273b528dd}

	// S0 = key ^ nonce
	s[0] = xor(key, nonce)
	// S1 = C1
	s[1] = C1
	// S2 = C0
	s[2] = C0
	// S3 = C1
	s[3] = C1
	// S4 = key ^ nonce
	s[4] = xor(key, nonce)
	// S5 = key ^ C0
	s[5] = xor(key, C0)
	// S6 = key ^ C1
	s[6] = xor(key, C1)
	// S7 = key ^ C0
	s[7] = xor(key, C0)

	// Repeat(10, Update(nonce, key))
	for i := 0; i < 10; i++ {
		update128L(s, nonce, key)
	}
}

func update128L(s *[8]uint128, m0, m1 uint128) {
	// S'0 = AESRound(S7, S0 ^ M0)
	s0 := aesRound(s[7], xor(s[0], m0))
	// S'1 = AESRound(S0, S1)
	s1 := aesRound(s[0], s[1])
	// S'2 = AESRound(S1, S2)
	s2 := aesRound(s[1], s[2])
	// S'3 = AESRound(S2, S3)
	s3 := aesRound(s[2], s[3])
	// S'4 = AESRound(S3, S4 ^ M1)
	s4 := aesRound(s[3], xor(s[4], m1))
	// S'5 = AESRound(S4, S5)
	s5 := aesRound(s[4], s[5])
	// S'6 = AESRound(S5, S6)
	s6 := aesRound(s[5], s[6])
	// S'7 = AESRound(S6, S7)
	s7 := aesRound(s[6], s[7])

	// S0  = S'0
	s[0] = s0
	// S1  = S'1
	s[1] = s1
	// S2  = S'2
	s[2] = s2
	// S3  = S'3
	s[3] = s3
	// S4  = S'4
	s[4] = s4
	// S5  = S'5
	s[5] = s5
	// S6  = S'6
	s[6] = s6
	// S7  = S'7
	s[7] = s7
}

func authBlocks128L(s *[8]uint128, src []byte) {
	// ad_blocks = Split(Pad(ad, 256), 256)
	// for xi in ad_blocks:
	//     Enc(xi)
	for len(src) >= 32 {
		authBlock128L(s, src[:32])
		src = src[32:]
	}
	if len(src) > 0 {
		buf := make([]byte, 32)
		copy(buf, src)
		authBlock128L(s, buf)
	}
}

func authBlock128L(s *[8]uint128, src []byte) {
	// t0, t1 = Split(xi, 128)
	t0 := readUint128(src[0:16])
	t1 := readUint128(src[16:32])
	// Update(t0, t1)
	update128L(s, t0, t1)
}

func encryptBlocks128L(s *[8]uint128, dst, src []byte) {
	// msg_blocks = Split(Pad(msg, 256), 256)
	// for xi in msg_blocks:
	//     ct = ct || Enc(xi)
	for len(src) >= 32 {
		encryptBlock128L(s, dst[:32], src[:32])
		src = src[32:]
		dst = dst[32:]
	}
	if len(src) > 0 {
		buf := make([]byte, 32)
		copy(buf, src)
		encryptBlock128L(s, buf, buf)
		copy(dst, buf)
	}
}

func encryptBlock128L(s *[8]uint128, dst, src []byte) {
	// z0 = S6 ^ S1 ^ (S2 & S3)
	z0 := xor(xor(s[6], s[1]), and(s[2], s[3]))
	// z1 = S2 ^ S5 ^ (S6 & S7)
	z1 := xor(xor(s[2], s[5]), and(s[6], s[7]))

	// t0, t1 = Split(xi, 128)
	t0 := readUint128(src[0:16])
	t1 := readUint128(src[16:32])
	// out0 = t0 ^ z0
	out0 := xor(t0, z0)
	// out1 = t1 ^ z1
	out1 := xor(t1, z1)

	// Update(t0, t1)
	update128L(s, t0, t1)
	// ci = out0 || out1
	putUint128(dst[0:16], out0)
	putUint128(dst[16:32], out1)
}

func decryptBlocks128L(s *[8]uint128, dst, src []byte) {
	// ct_blocks = Split(ct, 256)
	// cn = Tail(ct, |ct| mod 256)
	//
	// for ci in ct_blocks:
	//     msg = msg || Dec(ci)
	for len(src) >= 32 {
		decryptBlock128L(s, dst[:32], src[:32])
		src = src[32:]
		dst = dst[32:]
	}
	// if cn is not empty:
	//     msg = msg || DecPartial(cn)
	if len(src) > 0 {
		decryptPartialBlock128L(s, dst, src)
	}
}

func decryptBlock128L(s *[8]uint128, dst, src []byte) {
	// z0 = S6 ^ S1 ^ (S2 & S3)
	z0 := xor(xor(s[6], s[1]), and(s[2], s[3]))
	// z1 = S2 ^ S5 ^ (S6 & S7)
	z1 := xor(xor(s[2], s[5]), and(s[6], s[7]))

	// t0, t1 = Split(ci, 128)
	t0 := readUint128(src[0:16])
	t1 := readUint128(src[16:32])
	// out0 = t0 ^ z0
	out0 := xor(t0, z0)
	// out1 = t1 ^ z1
	out1 := xor(t1, z1)

	// Update(out0, out1)
	update128L(s, out0, out1)
	// xi = out0 || out1
	putUint128(dst[0:16], out0)
	putUint128(dst[16:32], out1)
}

func decryptPartialBlock128L(s *[8]uint128, dst, src []byte) {
	// z0 = S6 ^ S1 ^ (S2 & S3)
	z0 := xor(xor(s[6], s[1]), and(s[2], s[3]))
	// z1 = S2 ^ S5 ^ (S6 & S7)
	z1 := xor(xor(s[2], s[5]), and(s[6], s[7]))

	cn := make([]byte, 32)
	copy(cn, src)

	// t0, t1 = Split(Pad(cn, 256), 128)
	t0 := readUint128(cn[0:16])
	t1 := readUint128(cn[16:32])
	// out0 = t0 ^ z0
	out0 := xor(t0, z0)
	// out1 = t1 ^ z1
	out1 := xor(t1, z1)

	// xn = Truncate(out0 || out1, |cn|)
	xn := make([]byte, 32)
	putUint128(xn[0:16], out0)
	putUint128(xn[16:32], out1)
	copy(dst, xn[:len(src)])

	for i := len(src); i < len(xn); i++ {
		xn[i] = 0
	}

	// v0, v1 = Split(Pad(xn, 256), 128)
	v0 := readUint128(xn[0:16])
	v1 := readUint128(xn[16:32])
	// Update(v0, v1)
	update128L(s, v0, v1)
}

func finalize128L(s *[8]uint128, dst []byte, adLen, mdLen int) {
	// TODO(eric): big-endian CPUs.

	// t = S2 ^ (LE64(ad_len) || LE64(msg_len))
	t := xor(s[2], uint128{
		hi: bits.ReverseBytes64(uint64(adLen)),
		lo: bits.ReverseBytes64(uint64(mdLen)),
	})
	// Repeat(7, Update(t, t))
	for i := 0; i < 7; i++ {
		update128L(s, t, t)
	}
	// tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
	var tag uint128
	tag = xor(s[0], s[1])
	tag = xor(tag, s[2])
	tag = xor(tag, s[3])
	tag = xor(tag, s[4])
	tag = xor(tag, s[5])
	tag = xor(tag, s[6])
	putUint128(dst[0:16], tag)
}

type uint128 struct {
	hi, lo uint64
}

func (x uint128) String() string {
	return fmt.Sprintf("{%#0.16x %#0.16x}", x.hi, x.lo)
}

func readUint128(p []byte) uint128 {
	return uint128{
		hi: binary.BigEndian.Uint64(p[0:8]),
		lo: binary.BigEndian.Uint64(p[8:16]),
	}
}

func putUint128(p []byte, x uint128) {
	binary.BigEndian.PutUint64(p[0:8], x.hi)
	binary.BigEndian.PutUint64(p[8:16], x.lo)
}

func xor(x, y uint128) uint128 {
	return uint128{hi: x.hi ^ y.hi, lo: x.lo ^ y.lo}
}

func and(x, y uint128) uint128 {
	return uint128{hi: x.hi & y.hi, lo: x.lo & y.lo}
}
