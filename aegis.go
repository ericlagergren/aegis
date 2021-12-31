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

	// KeySize256 is the size in bytes of an AEGIS-256 key.
	KeySize256 = 32
	// NonceSize256 is the size in bytes of an AEGIS-256 nonce.
	NonceSize256 = 32
	// TagSize256 is the size in bytes of an AEGIS-256
	// authentication tag.
	TagSize256 = 16
	// BlockSize256 is the size in bytes of an AEGIS-256 block.
	BlockSize256 = 16

	// plaintextMax256 is the size in bytes of the largest
	// allowed AESGIS-256 plaintext.
	plaintextMax256 = 1 << 61
	// ciphertextMax256 is the size in bytes of the largest
	// allowed AESGIS-256 ciphertext.
	ciphertextMax256 = plaintextMax256 + 16
	// adMax256 is the size in bytes of the largest allowed
	// AEGIS-256 additional data.
	adMax256 = 1 << 61
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
	case KeySize256:
		return new256(key), nil
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

	var s state128L

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

	var s state128L

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

type state128L [8]uint128

func init128L(s *state128L, key, nonce uint128) {
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

func update128L(s *state128L, m0, m1 uint128) {
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

	// S0 = S'0
	s[0] = s0
	// S1 = S'1
	s[1] = s1
	// S2 = S'2
	s[2] = s2
	// S3 = S'3
	s[3] = s3
	// S4 = S'4
	s[4] = s4
	// S5 = S'5
	s[5] = s5
	// S6 = S'6
	s[6] = s6
	// S7 = S'7
	s[7] = s7
}

func authBlocks128L(s *state128L, src []byte) {
	// ad_blocks = Split(Pad(ad, 256), 256)
	// for xi in ad_blocks:
	//     Enc(xi)
	for len(src) >= BlockSize128L {
		authBlock128L(s, src[:BlockSize128L])
		src = src[BlockSize128L:]
	}
	if len(src) > 0 {
		buf := make([]byte, BlockSize128L)
		copy(buf, src)
		authBlock128L(s, buf)
	}
}

func authBlock128L(s *state128L, src []byte) {
	// t0, t1 = Split(xi, 128)
	t0 := readUint128(src[0:16])
	t1 := readUint128(src[16:32])
	// Update(t0, t1)
	update128L(s, t0, t1)
}

func encryptBlocks128L(s *state128L, dst, src []byte) {
	// msg_blocks = Split(Pad(msg, 256), 256)
	// for xi in msg_blocks:
	//     ct = ct || Enc(xi)
	for len(src) >= BlockSize128L {
		encryptBlock128L(s, dst[:BlockSize128L], src[:BlockSize128L])
		src = src[BlockSize128L:]
		dst = dst[BlockSize128L:]
	}
	if len(src) > 0 {
		buf := make([]byte, BlockSize128L)
		copy(buf, src)
		encryptBlock128L(s, buf, buf)
		copy(dst, buf)
	}
}

func encryptBlock128L(s *state128L, dst, src []byte) {
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

func decryptBlocks128L(s *state128L, dst, src []byte) {
	// ct_blocks = Split(ct, 256)
	// cn = Tail(ct, |ct| mod 256)
	//
	// for ci in ct_blocks:
	//     msg = msg || Dec(ci)
	for len(src) >= BlockSize128L {
		decryptBlock128L(s, dst[:BlockSize128L], src[:BlockSize128L])
		src = src[BlockSize128L:]
		dst = dst[BlockSize128L:]
	}
	// if cn is not empty:
	//     msg = msg || DecPartial(cn)
	if len(src) > 0 {
		decryptPartialBlock128L(s, dst, src)
	}
}

func decryptBlock128L(s *state128L, dst, src []byte) {
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

func decryptPartialBlock128L(s *state128L, dst, src []byte) {
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

func finalize128L(s *state128L, dst []byte, adLen, mdLen int) {
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

type aegis256 struct {
	key [2]uint128
}

func new256(key []byte) *aegis256 {
	return &aegis256{
		key: [2]uint128{
			{
				hi: binary.BigEndian.Uint64(key[0:8]),
				lo: binary.BigEndian.Uint64(key[8:16]),
			},
			{
				hi: binary.BigEndian.Uint64(key[16:24]),
				lo: binary.BigEndian.Uint64(key[24:32]),
			},
		},
	}
}

func (*aegis256) NonceSize() int {
	return NonceSize256
}

func (*aegis256) Overhead() int {
	return TagSize256
}

func (a *aegis256) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(plaintext) > plaintextMax256 {
		panic("aegis: plaintext too large")
	}
	if len(nonce) != NonceSize256 {
		panic("aegis: invalid nonce length")
	}
	if len(additionalData) > adMax256 {
		panic("aegis: additional data too large")
	}

	ret, out := subtle.SliceForAppend(dst, len(plaintext)+TagSize256)
	if subtle.InexactOverlap(out, plaintext) {
		panic("aegis: invalid buffer overlap")
	}

	var s state256

	// Init(key, nonce)
	n0 := readUint128(nonce[0:16])
	n1 := readUint128(nonce[16:32])
	init256(&s, a.key[0], a.key[1], n0, n1)

	// ad_blocks = Split(Pad(ad, 128), 128)
	// for xi in ad_blocks:
	//     Enc(xi)
	authBlocks256(&s, additionalData)

	// msg_blocks = Split(Pad(msg, 128), 128)
	// for xi in msg_blocks:
	//     ct = ct || Enc(xi)
	encryptBlocks256(&s, out[:len(plaintext)], plaintext)

	// tag = Finalize(|ad|, |msg|)
	finalize256(&s, out[len(out)-TagSize256:],
		len(additionalData)*8, len(plaintext)*8)

	return ret
}

func (a *aegis256) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize256 {
		panic("aegis: invalid nonce length")
	}
	if len(ciphertext) < TagSize256 ||
		len(ciphertext) > ciphertextMax256 ||
		len(additionalData) > adMax256 {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-TagSize256:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize256]

	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("aegis: invalid buffer overlap")
	}

	var s state256

	// Init(key, nonce)
	n0 := readUint128(nonce[0:16])
	n1 := readUint128(nonce[16:32])
	init256(&s, a.key[0], a.key[1], n0, n1)

	// ad_blocks = Split(Pad(ad, 128), 128)
	// for xi in ad_blocks:
	//     Enc(xi)
	authBlocks256(&s, additionalData)

	// ct_blocks = Split(ct, 128)
	// cn = Tail(ct, |ct| mod 128)
	//
	// for ci in ct_blocks:
	//     msg = msg || Dec(ci)
	// if cn is not empty:
	//     msg = msg || DecPartial(cn)
	decryptBlocks256(&s, out, ciphertext)

	// expected_tag = Finalize(|ad|, |msg|)
	expectedTag := make([]byte, TagSize256)
	finalize256(&s, expectedTag, len(additionalData)*8, len(out)*8)

	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		runtime.KeepAlive(out)
		return nil, errOpen
	}
	return ret, nil
}

type state256 [6]uint128

func init256(s *state256, k0, k1, n0, n1 uint128) {
	C0 := uint128{0x000101020305080d, 0x1522375990e97962}
	C1 := uint128{0xdb3d18556dc22ff1, 0x2011314273b528dd}

	// k0, k1 = Split(key, 128)
	// n0, n1 = Split(nonce, 128)

	// S0 = k0 ^ n0
	s[0] = xor(k0, n0)
	// S1 = k1 ^ n1
	s[1] = xor(k1, n1)
	// S2 = C1
	s[2] = C1
	// S3 = C0
	s[3] = C0
	// S4 = k0 ^ C0
	s[4] = xor(k0, C0)
	// S5 = k1 ^ C1
	s[5] = xor(k1, C1)

	// Repeat(4,
	//   Update(k0)
	//   Update(k1)
	//   Update(k0 ^ n0)
	//   Update(k1 ^ n1)
	// )
	for i := 0; i < 4; i++ {
		update256(s, k0)
		update256(s, k1)
		update256(s, xor(k0, n0))
		update256(s, xor(k1, n1))
	}
}

func update256(s *state256, m uint128) {
	// S'0 = AESRound(S5, S0 ^ M)
	s0 := aesRound(s[5], xor(s[0], m))
	// S'1 = AESRound(S0, S1)
	s1 := aesRound(s[0], s[1])
	// S'2 = AESRound(S1, S2)
	s2 := aesRound(s[1], s[2])
	// S'3 = AESRound(S2, S3)
	s3 := aesRound(s[2], s[3])
	// S'4 = AESRound(S3, S4)
	s4 := aesRound(s[3], s[4])
	// S'5 = AESRound(S4, S5)
	s5 := aesRound(s[4], s[5])

	// S0 = S'0
	s[0] = s0
	// S1 = S'1
	s[1] = s1
	// S2 = S'2
	s[2] = s2
	// S3 = S'3
	s[3] = s3
	// S4 = S'4
	s[4] = s4
	// S5 = S'5
	s[5] = s5
}

func authBlocks256(s *state256, src []byte) {
	// ad_blocks = Split(Pad(ad, 128), 128)
	// for xi in ad_blocks:
	//     Enc(xi)
	for len(src) >= BlockSize256 {
		authBlock256(s, src[:BlockSize256])
		src = src[BlockSize256:]
	}
	if len(src) > 0 {
		buf := make([]byte, BlockSize256)
		copy(buf, src)
		authBlock256(s, buf)
	}
}

func authBlock256(s *state256, src []byte) {
	// Update(xi)
	update256(s, readUint128(src[0:16]))
}

func encryptBlocks256(s *state256, dst, src []byte) {
	// msg_blocks = Split(Pad(msg, 128), 128)
	// for xi in msg_blocks:
	//     ct = ct || Enc(xi)
	for len(src) >= BlockSize256 {
		encryptBlock256(s, dst[:BlockSize256], src[:BlockSize256])
		src = src[BlockSize256:]
		dst = dst[BlockSize256:]
	}
	if len(src) > 0 {
		buf := make([]byte, BlockSize256)
		copy(buf, src)
		encryptBlock256(s, buf, buf)
		copy(dst, buf)
	}
}

func encryptBlock256(s *state256, dst, src []byte) {
	// z = S1 ^ S4 ^ S5 ^ (S2 & S3)
	z := xor(xor(xor(s[1], s[4]), s[5]), and(s[2], s[3]))
	xi := readUint128(src[0:16])
	// Update(xi)
	update256(s, xi)
	// ci = xi ^ z
	putUint128(dst[0:16], xor(xi, z))
}

func decryptBlocks256(s *state256, dst, src []byte) {
	// ct_blocks = Split(Pad(ct), 128)
	// cn = Tail(ct, |ct| mod 128)
	//
	// for ci in ct_blocks:
	//     msg = msg || Dec(ci)
	for len(src) >= BlockSize256 {
		decryptBlock256(s, dst[:BlockSize256], src[:BlockSize256])
		src = src[BlockSize256:]
		dst = dst[BlockSize256:]
	}
	// if cn is not empty:
	//     msg = msg || DecPartial(cn)
	if len(src) > 0 {
		decryptPartialBlock256(s, dst, src)
	}
}

func decryptBlock256(s *state256, dst, src []byte) {
	// z = S1 ^ S4 ^ S5 ^ (S2 & S3)
	z := xor(xor(xor(s[1], s[4]), s[5]), and(s[2], s[3]))
	// xi = ci ^ z
	xi := xor(readUint128(src[0:16]), z)
	putUint128(dst[0:16], xi)
	// Update(xi)
	update256(s, xi)
}

func decryptPartialBlock256(s *state256, dst, src []byte) {
	// z = S1 ^ S4 ^ S5 ^ (S2 & S3)
	z := xor(xor(xor(s[1], s[4]), s[5]), and(s[2], s[3]))

	// t = Pad(ci, 128)
	t := make([]byte, 16)
	copy(t, src)

	// out = t ^ z
	out := xor(readUint128(t), z)

	// xn = Truncate(out, |cn|)
	xn := make([]byte, 16)
	putUint128(xn, out)
	copy(dst, xn[:len(src)])

	// v = Pad(xn, 128)
	for i := len(src); i < len(xn); i++ {
		xn[i] = 0
	}
	v := readUint128(xn)

	// Update(v)
	update256(s, v)
}

func finalize256(s *state256, dst []byte, adLen, mdLen int) {
	// TODO(eric): big-endian CPUs.

	// t = S3 ^ (LE64(ad_len) || LE64(msg_len))
	t := xor(s[3], uint128{
		hi: bits.ReverseBytes64(uint64(adLen)),
		lo: bits.ReverseBytes64(uint64(mdLen)),
	})

	// Repeat(7, Update(t))
	for i := 0; i < 7; i++ {
		update256(s, t)
	}

	// tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5
	var tag uint128
	tag = xor(s[0], s[1])
	tag = xor(tag, s[2])
	tag = xor(tag, s[3])
	tag = xor(tag, s[4])
	tag = xor(tag, s[5])
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
