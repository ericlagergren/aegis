package aegis

import (
	"encoding/binary"
	"math/bits"

	"github.com/ericlagergren/subtle"
)

type state128L struct {
	s0, s1, s2, s3, s4, s5, s6, s7 uint128
}

func seal128LGeneric(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, plaintext, additionalData []byte) {
	var s state128L

	// Init(key, nonce)
	init128L(&s, readUint128(key[:]), readUint128(nonce[:]))

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
}

func open128LGeneric(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, ciphertext, tag, additionalData []byte) bool {
	var s state128L

	// Init(key, nonce)
	init128L(&s, readUint128(key[:]), readUint128(nonce[:]))

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

	return subtle.ConstantTimeCompare(expectedTag, tag) == 1
}

func init128L(s *state128L, key, nonce uint128) {
	C0 := uint128{0x000101020305080d, 0x1522375990e97962}
	C1 := uint128{0xdb3d18556dc22ff1, 0x2011314273b528dd}

	// S0 = key ^ nonce
	s.s0 = xor(key, nonce)
	// S1 = C1
	s.s1 = C1
	// S2 = C0
	s.s2 = C0
	// S3 = C1
	s.s3 = C1
	// S4 = key ^ nonce
	s.s4 = xor(key, nonce)
	// S5 = key ^ C0
	s.s5 = xor(key, C0)
	// S6 = key ^ C1
	s.s6 = xor(key, C1)
	// S7 = key ^ C0
	s.s7 = xor(key, C0)

	// Repeat(10, Update(nonce, key))
	for i := 0; i < 10; i++ {
		update128LGeneric(s, nonce, key)
	}
}

func update128LGeneric(s *state128L, m0, m1 uint128) {
	// S'0 = AESRound(S7, S0 ^ M0)
	s0 := aesRoundGeneric(s.s7, xor(s.s0, m0))
	// S'1 = AESRound(S0, S1)
	s1 := aesRoundGeneric(s.s0, s.s1)
	// S'2 = AESRound(S1, S2)
	s2 := aesRoundGeneric(s.s1, s.s2)
	// S'3 = AESRound(S2, S3)
	s3 := aesRoundGeneric(s.s2, s.s3)
	// S'4 = AESRound(S3, S4 ^ M1)
	s4 := aesRoundGeneric(s.s3, xor(s.s4, m1))
	// S'5 = AESRound(S4, S5)
	s5 := aesRoundGeneric(s.s4, s.s5)
	// S'6 = AESRound(S5, S6)
	s6 := aesRoundGeneric(s.s5, s.s6)
	// S'7 = AESRound(S6, S7)
	s7 := aesRoundGeneric(s.s6, s.s7)

	// S0 = S'0
	s.s0 = s0
	// S1 = S'1
	s.s1 = s1
	// S2 = S'2
	s.s2 = s2
	// S3 = S'3
	s.s3 = s3
	// S4 = S'4
	s.s4 = s4
	// S5 = S'5
	s.s5 = s5
	// S6 = S'6
	s.s6 = s6
	// S7 = S'7
	s.s7 = s7
}

func authBlocks128L(s *state128L, src []byte) {
	// ad_blocks = Split(Pad(ad, 256), 256)
	// for xi in ad_blocks:
	//     Enc(xi)
	for len(src) >= BlockSize128L {
		t0 := readUint128(src[0:16])
		t1 := readUint128(src[16:32])
		update128LGeneric(s, t0, t1)
		src = src[BlockSize128L:]
	}
	if len(src) > 0 {
		buf := make([]byte, BlockSize128L)
		copy(buf, src)
		t0 := readUint128(buf[0:16])
		t1 := readUint128(buf[16:32])
		update128LGeneric(s, t0, t1)
	}
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
	z0 := xor(xor(s.s6, s.s1), and(s.s2, s.s3))
	// z1 = S2 ^ S5 ^ (S6 & S7)
	z1 := xor(xor(s.s2, s.s5), and(s.s6, s.s7))

	// t0, t1 = Split(xi, 128)
	t0 := readUint128(src[0:16])
	t1 := readUint128(src[16:32])
	// out0 = t0 ^ z0
	out0 := xor(t0, z0)
	// out1 = t1 ^ z1
	out1 := xor(t1, z1)

	// Update(t0, t1)
	update128LGeneric(s, t0, t1)
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
	z0 := xor(xor(s.s6, s.s1), and(s.s2, s.s3))
	// z1 = S2 ^ S5 ^ (S6 & S7)
	z1 := xor(xor(s.s2, s.s5), and(s.s6, s.s7))

	// t0, t1 = Split(ci, 128)
	t0 := readUint128(src[0:16])
	t1 := readUint128(src[16:32])
	// out0 = t0 ^ z0
	out0 := xor(t0, z0)
	// out1 = t1 ^ z1
	out1 := xor(t1, z1)

	// Update(out0, out1)
	update128LGeneric(s, out0, out1)
	// xi = out0 || out1
	putUint128(dst[0:16], out0)
	putUint128(dst[16:32], out1)
}

func decryptPartialBlock128L(s *state128L, dst, src []byte) {
	// z0 = S6 ^ S1 ^ (S2 & S3)
	z0 := xor(xor(s.s6, s.s1), and(s.s2, s.s3))
	// z1 = S2 ^ S5 ^ (S6 & S7)
	z1 := xor(xor(s.s2, s.s5), and(s.s6, s.s7))

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
	update128LGeneric(s, v0, v1)
}

func finalize128L(s *state128L, dst []byte, adLen, mdLen int) {
	// TODO(eric): big-endian CPUs.

	// t = S2 ^ (LE64(ad_len) || LE64(msg_len))
	t := xor(s.s2, uint128{
		hi: bits.ReverseBytes64(uint64(adLen)),
		lo: bits.ReverseBytes64(uint64(mdLen)),
	})
	// Repeat(7, Update(t, t))
	for i := 0; i < 7; i++ {
		update128LGeneric(s, t, t)
	}
	// tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
	var tag uint128
	tag = xor(s.s0, s.s1)
	tag = xor(tag, s.s2)
	tag = xor(tag, s.s3)
	tag = xor(tag, s.s4)
	tag = xor(tag, s.s5)
	tag = xor(tag, s.s6)
	putUint128(dst[0:16], tag)
}

type state256 struct {
	s0, s1, s2, s3, s4, s5 uint128
}

func seal256Generic(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, plaintext, additionalData []byte) {
	var s state256

	// Init(key, nonce)
	init256(&s,
		readUint128(key[0:16]), readUint128(key[16:32]),
		readUint128(nonce[0:16]), readUint128(nonce[16:32]))

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
}

func open256Generic(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, ciphertext, tag, additionalData []byte) bool {
	var s state256

	// Init(key, nonce)
	init256(&s,
		readUint128(key[0:16]), readUint128(key[16:32]),
		readUint128(nonce[0:16]), readUint128(nonce[16:32]))

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

	return subtle.ConstantTimeCompare(expectedTag, tag) == 1
}

func init256(s *state256, k0, k1, n0, n1 uint128) {
	C0 := uint128{0x000101020305080d, 0x1522375990e97962}
	C1 := uint128{0xdb3d18556dc22ff1, 0x2011314273b528dd}

	// k0, k1 = Split(key, 128)
	// n0, n1 = Split(nonce, 128)

	// S0 = k0 ^ n0
	s.s0 = xor(k0, n0)
	// S1 = k1 ^ n1
	s.s1 = xor(k1, n1)
	// S2 = C1
	s.s2 = C1
	// S3 = C0
	s.s3 = C0
	// S4 = k0 ^ C0
	s.s4 = xor(k0, C0)
	// S5 = k1 ^ C1
	s.s5 = xor(k1, C1)

	// Repeat(4,
	//   Update(k0)
	//   Update(k1)
	//   Update(k0 ^ n0)
	//   Update(k1 ^ n1)
	// )
	for i := 0; i < 4; i++ {
		update256Generic(s, k0)
		update256Generic(s, k1)
		update256Generic(s, xor(k0, n0))
		update256Generic(s, xor(k1, n1))
	}
}

func update256Generic(s *state256, m uint128) {
	// S'0 = AESRound(S5, S0 ^ M)
	s0 := aesRoundGeneric(s.s5, xor(s.s0, m))
	// S'1 = AESRound(S0, S1)
	s1 := aesRoundGeneric(s.s0, s.s1)
	// S'2 = AESRound(S1, S2)
	s2 := aesRoundGeneric(s.s1, s.s2)
	// S'3 = AESRound(S2, S3)
	s3 := aesRoundGeneric(s.s2, s.s3)
	// S'4 = AESRound(S3, S4)
	s4 := aesRoundGeneric(s.s3, s.s4)
	// S'5 = AESRound(S4, S5)
	s5 := aesRoundGeneric(s.s4, s.s5)

	// S0 = S'0
	s.s0 = s0
	// S1 = S'1
	s.s1 = s1
	// S2 = S'2
	s.s2 = s2
	// S3 = S'3
	s.s3 = s3
	// S4 = S'4
	s.s4 = s4
	// S5 = S'5
	s.s5 = s5
}

func authBlocks256(s *state256, src []byte) {
	// ad_blocks = Split(Pad(ad, 128), 128)
	// for xi in ad_blocks:
	//     Enc(xi)
	for len(src) >= BlockSize256 {
		update256Generic(s, readUint128(src[0:16]))
		src = src[BlockSize256:]
	}
	if len(src) > 0 {
		buf := make([]byte, BlockSize256)
		copy(buf, src)
		update256Generic(s, readUint128(buf[0:16]))
	}
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
	z := xor(xor(xor(s.s1, s.s4), s.s5), and(s.s2, s.s3))
	xi := readUint128(src[0:16])
	// Update(xi)
	update256Generic(s, xi)
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
	z := xor(xor(xor(s.s1, s.s4), s.s5), and(s.s2, s.s3))
	// xi = ci ^ z
	xi := xor(readUint128(src[0:16]), z)
	putUint128(dst[0:16], xi)
	// Update(xi)
	update256Generic(s, xi)
}

func decryptPartialBlock256(s *state256, dst, src []byte) {
	// z = S1 ^ S4 ^ S5 ^ (S2 & S3)
	z := xor(xor(xor(s.s1, s.s4), s.s5), and(s.s2, s.s3))

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
	update256Generic(s, v)
}

func finalize256(s *state256, dst []byte, adLen, mdLen int) {
	// TODO(eric): big-endian CPUs.

	// t = S3 ^ (LE64(ad_len) || LE64(msg_len))
	t := xor(s.s3, uint128{
		hi: bits.ReverseBytes64(uint64(adLen)),
		lo: bits.ReverseBytes64(uint64(mdLen)),
	})

	// Repeat(7, Update(t))
	for i := 0; i < 7; i++ {
		update256Generic(s, t)
	}

	// tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5
	var tag uint128
	tag = xor(s.s0, s.s1)
	tag = xor(tag, s.s2)
	tag = xor(tag, s.s3)
	tag = xor(tag, s.s4)
	tag = xor(tag, s.s5)
	putUint128(dst[0:16], tag)
}

type uint128 struct {
	hi, lo uint64
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
