//go:build gc && !purego

#include "textflag.h"

// Registers V{0..10} are reserved.

// State registers.
#define s0 V0
#define s1 V1
#define s2 V2
#define s3 V3
#define s4 V4
#define s5 V5
#define s6 V6
#define s7 V7
#define stmp0 V8
#define stmp1 V9

// Zero register.
#define zero V10

// func copy32(dst, src []byte)
TEXT ·copy32(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R8
	MOVD src_base+24(FP), R1
	MOVD src_len+32(FP), R3
	CALL copy32<>(SB)
	RET

// copy32 copies R3 bytes for 0 < R3 < 32 from R1 to R8.
//
// copy32 does not modify the value in R3, R1, or R8.
//
// copy32 is borrowed from runtime.memmove.
TEXT copy32<>(SB), NOSPLIT|NOFRAME, $0-0
#define src_ptr R1
#define len R3
#define dst_ptr R8
#define srcend R9
#define dstend R10
// Data use R{11..14}

	CBZ len, copy0

	// Small copies: 1..16 bytes
	CMP $16, len
	BLE copy16

	// Small copies: 17..32 bytes.
	LDP (src_ptr), (R11, R12)
	ADD src_ptr, len, srcend    // srcend points just past the last source byte
	LDP -16(srcend), (R13, R14)
	STP (R11, R12), (dst_ptr)
	ADD dst_ptr, len, dstend    // dstend points just past the last destination byte
	STP (R13, R14), -16(dstend)
	RET

// Small copies: 1..16 bytes.
copy16:
	ADD  src_ptr, len, srcend // srcend points just past the last source byte
	ADD  dst_ptr, len, dstend // dstend points just past the last destination byte
	CMP  $8, len
	BLT  copy7
	MOVD (src_ptr), R11
	MOVD -8(srcend), R12
	MOVD R11, (dst_ptr)
	MOVD R12, -8(dstend)
	RET

copy7:
	TBZ   $2, len, copy3
	MOVWU (src_ptr), R11
	MOVWU -4(srcend), R12
	MOVW  R11, (dst_ptr)
	MOVW  R12, -4(dstend)
	RET

copy3:
	TBZ   $1, len, copy1
	MOVHU (src_ptr), R11
	MOVHU -2(srcend), R12
	MOVH  R11, (dst_ptr)
	MOVH  R12, -2(dstend)
	RET

copy1:
	MOVBU (src_ptr), R11
	MOVB  R11, (dst_ptr)

copy0:
	RET

#undef len
#undef src_ptr
#undef dst_ptr
#undef srcend
#undef dstend

// clear32 clears R3 bytes for 0 < R3 < 32 starting at R8.
//
// clear32 does not modify the value in R3 or R8.
TEXT clear32<>(SB), NOSPLIT|NOFRAME, $0-0
#define dst_ptr R8
#define len R3
#define dstend R9

	CBZ len, clear0

	// Small clear: 1..16 bytes
	CMP $16, len
	BLE clear16

	// Small clear: 17..32 bytes.
	STP (ZR, ZR), (dst_ptr)
	ADD dst_ptr, len, dstend  // dstend points just past the last destination byte
	STP (ZR, ZR), -16(dstend)
	RET

// Small clear: 1..16 bytes.
clear16:
	ADD  dst_ptr, len, dstend // dstend points just past the last destination byte
	CMP  $8, len
	BLT  clear7
	MOVD ZR, (dst_ptr)
	MOVD ZR, -8(dstend)
	RET

clear7:
	TBZ  $2, len, clear3
	MOVW ZR, (dst_ptr)
	MOVW ZR, -4(dstend)
	RET

clear3:
	TBZ  $1, len, clear1
	MOVH ZR, (dst_ptr)
	MOVH ZR, -2(dstend)
	RET

clear1:
	MOVB ZR, (dst_ptr)

clear0:
	RET

#undef dst_ptr
#undef len
#undef dstend

// INIT_ZERO initializes |zero| to $0x0.
//
// Every function must call this before (transitivelu) invoking
// AES_ROUND.
#define INIT_ZERO() VEOR zero.B16, zero.B16, zero.B16

// AES_ROUND performs one round of AES on |in|.
//
// Uses |zero|.
#define AES_ROUND(in, rk) \
	AESE  zero.B16, in.B16       \
	AESMC in.B16, in.B16         \
	VEOR  rk.B16, in.B16, in.B16

// UPDATE_STATE128L performs AEGIS-128L Update.
//
// Uses |s{0..7}|, |zero|, and |stmp{0,1}|.
#define UPDATE_STATE128L(m0, m1) \
	VMOV  s7.B16, stmp1.B16                 \
	                                        \
	VMOV  s6.B16, stmp0.B16                 \
	AESE  zero.B16, stmp0.B16               \
	AESMC stmp0.B16, stmp0.B16              \
	VEOR  s7.B16, stmp0.B16, s7.B16         \
	                                        \
	VMOV  s5.B16, stmp0.B16                 \
	AESE  zero.B16, stmp0.B16               \
	AESMC stmp0.B16, stmp0.B16              \
	VEOR  s6.B16, stmp0.B16, s6.B16         \
	                                        \
	VMOV  s4.B16, stmp0.B16                 \
	AESE  zero.B16, stmp0.B16               \
	AESMC stmp0.B16, stmp0.B16              \
	VEOR  s5.B16, stmp0.B16, s5.B16         \
	                                        \
	VMOV  s3.B16, stmp0.B16                 \
	AESE  zero.B16, stmp0.B16               \
	AESMC stmp0.B16, stmp0.B16              \
	VEOR3 s4.B16, m1.B16, stmp0.B16, s4.B16 \
	                                        \
	VMOV  s2.B16, stmp0.B16                 \
	AESE  zero.B16, stmp0.B16               \
	AESMC stmp0.B16, stmp0.B16              \
	VEOR  s3.B16, stmp0.B16, s3.B16         \
	                                        \
	VMOV  s1.B16, stmp0.B16                 \
	AESE  zero.B16, stmp0.B16               \
	AESMC stmp0.B16, stmp0.B16              \
	VEOR  s2.B16, stmp0.B16, s2.B16         \
	                                        \
	VMOV  s0.B16, stmp0.B16                 \
	AESE  zero.B16, stmp0.B16               \
	AESMC stmp0.B16, stmp0.B16              \
	VEOR  s1.B16, stmp0.B16, s1.B16         \
	                                        \
	AESE  zero.B16, stmp1.B16               \
	AESMC stmp1.B16, stmp1.B16              \
	VEOR3 s0.B16, m0.B16, stmp1.B16, s0.B16

// func update128L(s *state128L, m *[BlockSize128L]byte)
TEXT ·update128L(SB), NOSPLIT, $0-16
#define s_ptr R0
#define m_ptr R1
#define m0 V30
#define m1 V31

#define REVERSE_STATE() \
	VREV64 s0.B16, s0.B16 \
	VREV64 s1.B16, s1.B16 \
	VREV64 s2.B16, s2.B16 \
	VREV64 s3.B16, s3.B16 \
	VREV64 s4.B16, s4.B16 \
	VREV64 s5.B16, s5.B16 \
	VREV64 s6.B16, s6.B16 \
	VREV64 s7.B16, s7.B16 \

	INIT_ZERO()
	LDP    s+0(FP), (s_ptr, m_ptr)
	VLD1.P 64(s_ptr), [s0.B16, s1.B16, s2.B16, s3.B16]
	VLD1.P 64(s_ptr), [s4.B16, s5.B16, s6.B16, s7.B16]
	REVERSE_STATE()
	VLD1   (m_ptr), [m0.B16, m1.B16]
	UPDATE_STATE128L(m0, m1)
	REVERSE_STATE()
	SUB    $128, s_ptr
	VST1.P [s0.B16, s1.B16, s2.B16, s3.B16], 64(s_ptr)
	VST1.P [s4.B16, s5.B16, s6.B16, s7.B16], 64(s_ptr)
	RET

#undef REVERSE_STATE
#undef s_ptr
#undef m_ptr
#undef m0
#undef m1

// func seal128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, plaintext, additionalData []byte)
TEXT ·seal128L(SB), 0, $32-88
#define src_ptr R1
#define dst_ptr R2
#define remain R3
#define key_ptr R4
#define nonce_ptr R5
#define ad_len R6
#define pt_len R7
#define stack_ptr R8

#define vkey V11
#define vnonce V12
#define C0 V13
#define C1 V14
#define z0 V15
#define z1 V16
#define t0 V17
#define t1 V18
#define out0 V19
#define out1 V20
#define t V21
#define tag V22

	INIT_ZERO()

	MOVD out_base+16(FP), dst_ptr

	MOVD RSP, stack_ptr
	SUB  $32, stack_ptr

initState:
	VMOVQ $0x0d08050302010100, $0x6279e99059372215, C0
	VMOVQ $0xf12fc26d55183ddb, $0xdd28b57342311120, C1

	MOVD key+0(FP), key_ptr
	MOVD nonce+8(FP), nonce_ptr

	// S0 = key ^ nonce
	VLD1 (key_ptr), [vkey.B16]
	VLD1 (nonce_ptr), [vnonce.B16]
	VEOR vkey.B16, vnonce.B16, s0.B16

	// S1 = C1
	VMOV C1.B16, s1.B16

	// S2 = C0
	VMOV C0.B16, s2.B16

	// S3 = C1
	VMOV C1.B16, s3.B16

	// S4 = key ^ nonce
	VEOR vkey.B16, vnonce.B16, s4.B16

	// S5 = key ^ C0
	VEOR vkey.B16, C0.B16, s5.B16

	// S6 = key ^ C1
	VEOR vkey.B16, C1.B16, s6.B16

	// S7 = key ^ C0
	VEOR vkey.B16, C0.B16, s7.B16

	// Repeat(10, Update(nonce, key))
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)

auth:
	MOVD additionalData_len+72(FP), remain
	CBZ  remain, encrypt

	MOVD additionalData_base+64(FP), src_ptr
	CMP  $32, remain
	BLT  authPartial

authFull:
	// t0, t1 = Split(xi, 128)
	VLD1.P 32(src_ptr), [t0.B16, t1.B16]

	// Update(t0, t1)
	UPDATE_STATE128L(t0, t1)

	SUB $32, remain, remain
	CMP $32, remain
	BGE authFull
	CBZ remain, encrypt

authPartial:
	STP  (ZR, ZR), (0*8)(stack_ptr)
	STP  (ZR, ZR), (2*8)(stack_ptr)
	CALL copy32<>(SB)

	// t0, t1 = Split(xi, 128)
	VLD1 (stack_ptr), [t0.B16, t1.B16]

	// Update(t0, t1)
	UPDATE_STATE128L(t0, t1)

encrypt:
	MOVD plaintext_len+48(FP), remain
	CBZ  remain, finalize

	MOVD plaintext_base+40(FP), src_ptr
	CMP  $32, remain
	BLT  encryptPartial

encryptFull:
	// z0 = S6 ^ S1 ^ (S2 & S3)
	VAND  s2.B16, s3.B16, z0.B16
	VEOR3 s6.B16, s1.B16, z0.B16, z0.B16

	// z1 = S2 ^ S5 ^ (S6 & S7)
	VAND  s6.B16, s7.B16, z1.B16
	VEOR3 s2.B16, s5.B16, z1.B16, z1.B16

	// t0, t1 = Split(xi, 128)
	VLD1.P 32(src_ptr), [t0.B16, t1.B16]

	// out0 = t0 ^ z0
	// out1 = t1 ^ z1
	VEOR t0.B16, z0.B16, out0.B16
	VEOR t1.B16, z1.B16, out1.B16

	// Update(t0, t1)
	UPDATE_STATE128L(t0, t1)

	// ci = out0 || out1
	VST1.P [out0.B16, out1.B16], 32(dst_ptr)

	SUB $32, remain, remain
	CMP $32, remain
	BGE encryptFull
	CBZ remain, finalize

encryptPartial:
	// z0 = S6 ^ S1 ^ (S2 & S3)
	VAND  s2.B16, s3.B16, z0.B16
	VEOR3 s6.B16, s1.B16, z0.B16, z0.B16

	// z1 = S2 ^ S5 ^ (S6 & S7)
	VAND  s6.B16, s7.B16, z1.B16
	VEOR3 s2.B16, s5.B16, z1.B16, z1.B16

	STP  (ZR, ZR), (0*8)(stack_ptr)
	STP  (ZR, ZR), (2*8)(stack_ptr)
	CALL copy32<>(SB)

	// t0, t1 = Split(xi, 128)
	VLD1 (stack_ptr), [t0.B16, t1.B16]

	// out0 = t0 ^ z0
	// out1 = t1 ^ z1
	VEOR t0.B16, z0.B16, out0.B16
	VEOR t1.B16, z1.B16, out1.B16

	// Update(t0, t1)
	UPDATE_STATE128L(t0, t1)

	// ci = out0 || out1
	VST1 [out0.B16, out1.B16], (stack_ptr)
	MOVD stack_ptr, src_ptr                // read from stack_ptr
	MOVD dst_ptr, stack_ptr                // write to dst_ptr
	CALL copy32<>(SB)
	MOVD src_ptr, stack_ptr                // reset stack_ptr
	ADD  remain, dst_ptr

finalize:
	// t = S2 ^ (LE64(ad_len) || LE64(msg_len))
	MOVD additionalData_len+72(FP), ad_len
	MOVD plaintext_len+48(FP), pt_len
	LSL  $3, ad_len
	LSL  $3, pt_len
	STP  (ad_len, pt_len), (stack_ptr)
	VLD1 (stack_ptr), [t.B16]
	VEOR s2.B16, t.B16, t.B16

	// Repeat(7, Update(t, t))
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)

	// tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
	VEOR3 s0.B16, s1.B16, s2.B16, tag.B16
	VEOR3 s3.B16, s4.B16, tag.B16, tag.B16
	VEOR3 s5.B16, s6.B16, tag.B16, tag.B16

	VST1 [tag.B16], (dst_ptr)

	RET

#undef src_ptr
#undef dst_ptr
#undef remain
#undef key_ptr
#undef nonce_ptr
#undef ad_len
#undef pt_len
#undef stack_ptr

#undef vkey
#undef vnonce
#undef C0
#undef C1
#undef z0
#undef z1
#undef t0
#undef t1
#undef out0
#undef out1
#undef t
#undef tag

// func open128L(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, expectedTag *[TagSize128L]byte, out, ciphertext, additionalData []byte)
TEXT ·open128L(SB), NOSPLIT, $32-96
#define src_ptr R1
#define dst_ptr R2
#define remain R3
#define key_ptr R4
#define nonce_ptr R5
#define ad_len R6
#define ct_len R7
#define stack_ptr R8

#define vkey V11
#define vnonce V12
#define C0 V13
#define C1 V14
#define z0 V15
#define z1 V16
#define t0 V17
#define t1 V18
#define out0 V19
#define out1 V20
#define v0 V21
#define v1 V22
#define t V23
#define tag V24
#define fix0 V25
#define fix1 V26

	INIT_ZERO()

	MOVD out_base+24(FP), dst_ptr

	MOVD RSP, stack_ptr
	SUB  $32, stack_ptr

initState:
	VMOVQ $0x0d08050302010100, $0x6279e99059372215, C0
	VMOVQ $0xf12fc26d55183ddb, $0xdd28b57342311120, C1

	MOVD key+0(FP), key_ptr
	MOVD nonce+8(FP), nonce_ptr

	// S0 = key ^ nonce
	VLD1 (key_ptr), [vkey.B16]
	VLD1 (nonce_ptr), [vnonce.B16]
	VEOR vkey.B16, vnonce.B16, s0.B16

	// S1 = C1
	VMOV C1.B16, s1.B16

	// S2 = C0
	VMOV C0.B16, s2.B16

	// S3 = C1
	VMOV C1.B16, s3.B16

	// S4 = key ^ nonce
	VEOR vkey.B16, vnonce.B16, s4.B16

	// S5 = key ^ C0
	VEOR vkey.B16, C0.B16, s5.B16

	// S6 = key ^ C1
	VEOR vkey.B16, C1.B16, s6.B16

	// S7 = key ^ C0
	VEOR vkey.B16, C0.B16, s7.B16

	// Repeat(10, Update(nonce, key))
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)
	UPDATE_STATE128L(vnonce, vkey)

auth:
	MOVD additionalData_len+80(FP), remain
	CBZ  remain, decrypt

	MOVD additionalData_base+72(FP), src_ptr
	CMP  $32, remain
	BLT  authPartial

authFull:
	// t0, t1 = Split(xi, 128)
	VLD1.P 32(src_ptr), [t0.B16, t1.B16]

	// Update(t0, t1)
	UPDATE_STATE128L(t0, t1)

	SUB $32, remain, remain
	CMP $32, remain
	BGE authFull
	CBZ remain, decrypt

authPartial:
	STP  (ZR, ZR), (0*8)(stack_ptr)
	STP  (ZR, ZR), (2*8)(stack_ptr)
	CALL copy32<>(SB)

	// t0, t1 = Split(xi, 128)
	VLD1 (stack_ptr), [t0.B16, t1.B16]

	// Update(t0, t1)
	UPDATE_STATE128L(t0, t1)

decrypt:
	MOVD ciphertext_len+56(FP), remain
	CBZ  remain, finalize

	MOVD ciphertext_base+48(FP), src_ptr
	CMP  $32, remain
	BLT  decryptPartial

decryptFull:
	// z0 = S6 ^ S1 ^ (S2 & S3)
	VAND  s2.B16, s3.B16, z0.B16
	VEOR3 s6.B16, s1.B16, z0.B16, z0.B16

	// z1 = S2 ^ S5 ^ (S6 & S7)
	VAND  s6.B16, s7.B16, z1.B16
	VEOR3 s2.B16, s5.B16, z1.B16, z1.B16

	// t0, t1 = Split(ci, 128)
	VLD1.P 32(src_ptr), [t0.B16, t1.B16]

	// out0 = t0 ^ z0
	// out1 = t1 ^ z1
	VEOR t0.B16, z0.B16, out0.B16
	VEOR t1.B16, z1.B16, out1.B16

	// Update(out0, out1)
	UPDATE_STATE128L(out0, out1)

	// xi = out0 || out1
	VST1.P [out0.B16, out1.B16], 32(dst_ptr)

	SUB $32, remain, remain
	CMP $32, remain
	BGE decryptFull
	CBZ remain, finalize

decryptPartial:
	// z0 = S6 ^ S1 ^ (S2 & S3)
	VAND  s2.B16, s3.B16, z0.B16
	VEOR3 s6.B16, s1.B16, z0.B16, z0.B16

	// z1 = S2 ^ S5 ^ (S6 & S7)
	VAND  s6.B16, s7.B16, z1.B16
	VEOR3 s2.B16, s5.B16, z1.B16, z1.B16

	// t0, t1 = Split(Pad(cn, 256), 128)
	STP  (ZR, ZR), (0*8)(stack_ptr)
	STP  (ZR, ZR), (2*8)(stack_ptr)
	CALL copy32<>(SB)
	VLD1 (stack_ptr), [t0.B16, t1.B16]

	// out0 = t0 ^ z0
	// out1 = t1 ^ z1
	VEOR t0.B16, z0.B16, out0.B16
	VEOR t1.B16, z1.B16, out1.B16

	// xn = Truncate(out0 || out1, |cn|)
	STP  (ZR, ZR), (0*8)(stack_ptr)
	STP  (ZR, ZR), (2*8)(stack_ptr)
	VST1 [out0.B16, out1.B16], (stack_ptr)
	MOVD stack_ptr, src_ptr                // read from stack_ptr
	MOVD dst_ptr, stack_ptr                // write to dst_ptr
	CALL copy32<>(SB)
	MOVD src_ptr, stack_ptr                // reset stack_ptr

	// v0, v1 = Split(Pad(xn, 256), 128)
	VLD1 (stack_ptr), [v0.B16, v1.B16]

	// Update(v0, v1)
	UPDATE_STATE128L(v0, v1)

	// Fix s0 and s4 which were incorrectly calculated because
	// bytes 32-|cn| in |stack_ptr| weren't cleared before
	// loading (v0, v1). Alternatively, we could clear those
	// bits, but this results in simpler code.
	CALL clear32<>(SB)
	VLD1 (stack_ptr), [fix0.B16, fix1.B16]
	VEOR fix0.B16, s0.B16, s0.B16
	VEOR fix1.B16, s4.B16, s4.B16

finalize:
	// t = S2 ^ (LE64(ad_len) || LE64(msg_len))
	MOVD additionalData_len+80(FP), ad_len
	MOVD ciphertext_len+56(FP), ct_len
	LSL  $3, ad_len
	LSL  $3, ct_len
	STP  (ad_len, ct_len), (stack_ptr)
	VLD1 (stack_ptr), [t.B16]
	VEOR s2.B16, t.B16, t.B16

	// Repeat(7, Update(t, t))
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)
	UPDATE_STATE128L(t, t)

	// tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
	VEOR3 s0.B16, s1.B16, s2.B16, tag.B16
	VEOR3 s3.B16, s4.B16, tag.B16, tag.B16
	VEOR3 s5.B16, s6.B16, tag.B16, tag.B16

	MOVD expectedTag+16(FP), dst_ptr
	VST1 [tag.B16], (dst_ptr)

	RET

#undef src_ptr
#undef dst_ptr
#undef remain
#undef key_ptr
#undef nonce_ptr
#undef ad_len
#undef ct_len
#undef stack_ptr

#undef vkey
#undef vnonce
#undef C0
#undef C1
#undef z0
#undef z1
#undef t0
#undef t1
#undef out0
#undef out1
#undef v0
#undef v1
#undef t
#undef tag
#undef fix0
#undef fix1

// UPDATE_STATE256 performs AEGIS-256 Update.
//
// Uses |s{0..5}|, |zero|, and |stmp{0,1}|.
#define UPDATE_STATE256(m) \
	VMOV  s5.B16, stmp1.B16                \
	                                       \
	VMOV  s4.B16, stmp0.B16                \
	AESE  zero.B16, stmp0.B16              \
	AESMC stmp0.B16, stmp0.B16             \
	VEOR  s5.B16, stmp0.B16, s5.B16        \
	                                       \
	VMOV  s3.B16, stmp0.B16                \
	AESE  zero.B16, stmp0.B16              \
	AESMC stmp0.B16, stmp0.B16             \
	VEOR  s4.B16, stmp0.B16, s4.B16        \
	                                       \
	VMOV  s2.B16, stmp0.B16                \
	AESE  zero.B16, stmp0.B16              \
	AESMC stmp0.B16, stmp0.B16             \
	VEOR  s3.B16, stmp0.B16, s3.B16        \
	                                       \
	VMOV  s1.B16, stmp0.B16                \
	AESE  zero.B16, stmp0.B16              \
	AESMC stmp0.B16, stmp0.B16             \
	VEOR  s2.B16, stmp0.B16, s2.B16        \
	                                       \
	VMOV  s0.B16, stmp0.B16                \
	AESE  zero.B16, stmp0.B16              \
	AESMC stmp0.B16, stmp0.B16             \
	VEOR  s1.B16, stmp0.B16, s1.B16        \
	                                       \
	AESE  zero.B16, stmp1.B16              \
	AESMC stmp1.B16, stmp1.B16             \
	VEOR3 s0.B16, m.B16, stmp1.B16, s0.B16

// func update256(s *state256, m *[BlockSize256]byte)
TEXT ·update256(SB), NOSPLIT, $0-16
#define s_ptr R0
#define m_ptr R1
#define m V30

#define REVERSE_STATE() \
	VREV64 s0.B16, s0.B16 \
	VREV64 s1.B16, s1.B16 \
	VREV64 s2.B16, s2.B16 \
	VREV64 s3.B16, s3.B16 \
	VREV64 s4.B16, s4.B16 \
	VREV64 s5.B16, s5.B16 \

	INIT_ZERO()
	LDP    s+0(FP), (s_ptr, m_ptr)
	VLD1.P 64(s_ptr), [s0.B16, s1.B16, s2.B16, s3.B16]
	VLD1.P 32(s_ptr), [s4.B16, s5.B16]
	REVERSE_STATE()
	VLD1   (m_ptr), [m.B16]
	UPDATE_STATE256(m)
	REVERSE_STATE()
	SUB    $96, s_ptr
	VST1.P [s0.B16, s1.B16, s2.B16, s3.B16], 64(s_ptr)
	VST1.P [s4.B16, s5.B16], 32(s_ptr)
	RET

#undef REVERSE_STATE
#undef s_ptr
#undef m_ptr
#undef m

// func seal256(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, plaintext, additionalData []byte)
TEXT ·seal256(SB), NOSPLIT, $16-88
#define src_ptr R1
#define dst_ptr R2
#define remain R3
#define key_ptr R4
#define nonce_ptr R5
#define ad_len R6
#define pt_len R7
#define stack_ptr R8

#define k0 V11
#define k1 V12
#define n0 V13
#define n1 V14
#define kn0 V15
#define kn1 V16
#define C0 V17
#define C1 V18
#define z V19
#define xi V20
#define ci V21
#define t V22
#define tag V23

	INIT_ZERO()

	MOVD out_base+16(FP), dst_ptr

	MOVD RSP, stack_ptr
	SUB  $16, stack_ptr

initState:
	VMOVQ $0x0d08050302010100, $0x6279e99059372215, C0
	VMOVQ $0xf12fc26d55183ddb, $0xdd28b57342311120, C1

	MOVD key+0(FP), key_ptr
	MOVD nonce+8(FP), nonce_ptr
	VLD1 (key_ptr), [k0.B16, k1.B16]
	VLD1 (nonce_ptr), [n0.B16, n1.B16]

	// S0 = k0 ^ n0
	VEOR k0.B16, n0.B16, s0.B16

	// S1 = k1 ^ n1
	VEOR k1.B16, n1.B16, s1.B16

	// S2 = C1
	VMOV C1.B16, s2.B16

	// S3 = C0
	VMOV C0.B16, s3.B16

	// S4 = k0 ^ C0
	VEOR k0.B16, C0.B16, s4.B16

	// S5 = k1 ^ C1
	VEOR k1.B16, C1.B16, s5.B16

	// Repeat(4,
	//   Update(k0)
	//   Update(k1)
	//   Update(k0 ^ n0)
	//   Update(k1 ^ n1)
	// )
	VEOR k0.B16, n0.B16, kn0.B16
	VEOR k1.B16, n1.B16, kn1.B16

#define UPDATE() \
	UPDATE_STATE256(k0)  \
	UPDATE_STATE256(k1)  \
	UPDATE_STATE256(kn0) \
	UPDATE_STATE256(kn1)

	UPDATE()
	UPDATE()
	UPDATE()
	UPDATE()

#undef UPDATE

auth:
	MOVD additionalData_len+72(FP), remain
	CBZ  remain, encrypt

	MOVD additionalData_base+64(FP), src_ptr
	CMP  $16, remain
	BLT  authPartial

authFull:
	VLD1.P 16(src_ptr), [xi.B16]

	// Update(xi)
	UPDATE_STATE256(xi)

	SUB $16, remain, remain
	CMP $16, remain
	BGE authFull
	CBZ remain, encrypt

authPartial:
	STP  (ZR, ZR), (stack_ptr)
	CALL copy32<>(SB)
	VLD1 (stack_ptr), [xi.B16]

	// Update(xi)
	UPDATE_STATE256(xi)

encrypt:
	MOVD plaintext_len+48(FP), remain
	CBZ  remain, finalize

	MOVD plaintext_base+40(FP), src_ptr
	CMP  $16, remain
	BLT  encryptPartial

encryptFull:
	// z = S1 ^ S4 ^ S5 ^ (S2 & S3)
	VAND  s2.B16, s3.B16, z.B16
	VEOR3 s1.B16, s4.B16, z.B16, z.B16
	VEOR  s5.B16, z.B16, z.B16

	VLD1.P 16(src_ptr), [xi.B16]

	// Update(xi)
	UPDATE_STATE256(xi)

	// ci = xi ^ z
	VEOR   xi.B16, z.B16, ci.B16
	VST1.P [ci.B16], 16(dst_ptr)

	SUB $16, remain, remain
	CMP $16, remain
	BGE encryptFull
	CBZ remain, finalize

encryptPartial:
	// z = S1 ^ S4 ^ S5 ^ (S2 & S3)
	VAND  s2.B16, s3.B16, z.B16
	VEOR3 s1.B16, s4.B16, z.B16, z.B16
	VEOR  s5.B16, z.B16, z.B16

	STP  (ZR, ZR), (0*8)(stack_ptr)
	CALL copy32<>(SB)
	VLD1 (stack_ptr), [xi.B16]

	// Update(xi)
	UPDATE_STATE256(xi)

	// ci = xi ^ z
	VEOR xi.B16, z.B16, ci.B16
	VST1 [ci.B16], (stack_ptr)
	MOVD stack_ptr, src_ptr    // read from stack_ptr
	MOVD dst_ptr, stack_ptr    // write to dst_ptr
	CALL copy32<>(SB)
	MOVD src_ptr, stack_ptr    // reset stack_ptr
	ADD  remain, dst_ptr

finalize:
	// t = S3 ^ (LE64(ad_len) || LE64(msg_len))
	MOVD additionalData_len+72(FP), ad_len
	MOVD plaintext_len+48(FP), pt_len
	LSL  $3, ad_len
	LSL  $3, pt_len
	STP  (ad_len, pt_len), (stack_ptr)
	VLD1 (stack_ptr), [t.B16]
	VEOR s3.B16, t.B16, t.B16

	// Repeat(7, Update(t))
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)

	// tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5
	VEOR3 s0.B16, s1.B16, s2.B16, tag.B16
	VEOR3 s3.B16, s4.B16, tag.B16, tag.B16
	VEOR  s5.B16, tag.B16, tag.B16

	VST1 [tag.B16], (dst_ptr)

	RET

#undef src_ptr
#undef dst_ptr
#undef remain
#undef key_ptr
#undef nonce_ptr
#undef ad_len
#undef pt_len
#undef stack_ptr

#undef k0
#undef k1
#undef n0
#undef n1
#undef kn0
#undef kn1
#undef C0
#undef C1
#undef z
#undef xi
#undef ci
#undef t
#undef tag

// func open256(key *[KeySize256]byte, nonce *[NonceSize256]byte, expectedTag *[TagSize256]byte, out, ciphertext, additionalData []byte)
TEXT ·open256(SB), NOSPLIT, $0-96
#define src_ptr R1
#define dst_ptr R2
#define remain R3
#define key_ptr R4
#define nonce_ptr R5
#define ad_len R6
#define ct_len R7
#define stack_ptr R8

#define k0 V11
#define k1 V12
#define n0 V13
#define n1 V14
#define kn0 V15
#define kn1 V16
#define C0 V17
#define C1 V18
#define z V19
#define xi V20
#define ci V21
#define t V22
#define v V23
#define out V24
#define tag V25
#define fix V26

	INIT_ZERO()

	MOVD out_base+24(FP), dst_ptr

	MOVD RSP, stack_ptr
	SUB  $16, stack_ptr

initState:
	VMOVQ $0x0d08050302010100, $0x6279e99059372215, C0
	VMOVQ $0xf12fc26d55183ddb, $0xdd28b57342311120, C1

	MOVD key+0(FP), key_ptr
	MOVD nonce+8(FP), nonce_ptr
	VLD1 (key_ptr), [k0.B16, k1.B16]
	VLD1 (nonce_ptr), [n0.B16, n1.B16]

	// S0 = k0 ^ n0
	VEOR k0.B16, n0.B16, s0.B16

	// S1 = k1 ^ n1
	VEOR k1.B16, n1.B16, s1.B16

	// S2 = C1
	VMOV C1.B16, s2.B16

	// S3 = C0
	VMOV C0.B16, s3.B16

	// S4 = k0 ^ C0
	VEOR k0.B16, C0.B16, s4.B16

	// S5 = k1 ^ C1
	VEOR k1.B16, C1.B16, s5.B16

	// Repeat(4,
	//   Update(k0)
	//   Update(k1)
	//   Update(k0 ^ n0)
	//   Update(k1 ^ n1)
	// )
	VEOR k0.B16, n0.B16, kn0.B16
	VEOR k1.B16, n1.B16, kn1.B16

#define UPDATE() \
	UPDATE_STATE256(k0)  \
	UPDATE_STATE256(k1)  \
	UPDATE_STATE256(kn0) \
	UPDATE_STATE256(kn1)

	UPDATE()
	UPDATE()
	UPDATE()
	UPDATE()

#undef UPDATE

auth:
	MOVD additionalData_len+80(FP), remain
	CBZ  remain, decrypt

	MOVD additionalData_base+72(FP), src_ptr
	CMP  $16, remain
	BLT  authPartial

authFull:
	VLD1.P 16(src_ptr), [xi.B16]

	// Update(xi)
	UPDATE_STATE256(xi)

	SUB $16, remain, remain
	CMP $16, remain
	BGE authFull
	CBZ remain, decrypt

authPartial:
	STP  (ZR, ZR), (stack_ptr)
	CALL copy32<>(SB)
	VLD1 (stack_ptr), [xi.B16]

	// Update(xi)
	UPDATE_STATE256(xi)

decrypt:
	MOVD ciphertext_len+56(FP), remain
	CBZ  remain, finalize

	MOVD ciphertext_base+48(FP), src_ptr
	CMP  $16, remain
	BLT  decryptPartial

decryptFull:
	// z = S1 ^ S4 ^ S5 ^ (S2 & S3)
	VAND  s2.B16, s3.B16, z.B16
	VEOR3 s1.B16, s4.B16, z.B16, z.B16
	VEOR  s5.B16, z.B16, z.B16

	// xi = ci ^ z
	VLD1.P 16(src_ptr), [ci.B16]
	VEOR   ci.B16, z.B16, xi.B16
	VST1.P [xi.B16], 16(dst_ptr)

	// Update(xi)
	UPDATE_STATE256(xi)

	SUB $16, remain, remain
	CMP $16, remain
	BGE decryptFull
	CBZ remain, finalize

decryptPartial:
	// z = S1 ^ S4 ^ S5 ^ (S2 & S3)
	VAND  s2.B16, s3.B16, z.B16
	VEOR3 s1.B16, s4.B16, z.B16, z.B16
	VEOR  s5.B16, z.B16, z.B16

	// t = Pad(ci, 128)
	STP  (ZR, ZR), (0*8)(stack_ptr)
	CALL copy32<>(SB)
	VLD1 (stack_ptr), [t.B16]

	// out = t ^ z
	VEOR t.B16, z.B16, out.B16

	// xn = Truncate(out, |cn|)
	VST1 [out.B16], (stack_ptr)
	MOVD stack_ptr, src_ptr     // read from stack_ptr
	MOVD dst_ptr, stack_ptr     // write to dst_ptr
	CALL copy32<>(SB)
	MOVD src_ptr, stack_ptr     // reset stack_ptr

	// v = Pad(xn, 128)
	VLD1 (stack_ptr), [v.B16]

	// Update(v)
	UPDATE_STATE256(v)

	// Fix s0 which was incorrectly calculated because 16-|cn|
	// bytes in |stack_ptr| weren't cleared before loading v.
	// Alternatively, we could clear those bits, but this
	// results in simpler code.
	CALL clear32<>(SB)
	VLD1 (stack_ptr), [fix.B16]
	VEOR fix.B16, s0.B16, s0.B16

finalize:
	// t = S3 ^ (LE64(ad_len) || LE64(msg_len))
	MOVD additionalData_len+80(FP), ad_len
	MOVD ciphertext_len+56(FP), ct_len
	LSL  $3, ad_len
	LSL  $3, ct_len
	STP  (ad_len, ct_len), (stack_ptr)
	VLD1 (stack_ptr), [t.B16]
	VEOR s3.B16, t.B16, t.B16

	// Repeat(7, Update(t, t))
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)
	UPDATE_STATE256(t)

	// tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5
	VEOR3 s0.B16, s1.B16, s2.B16, tag.B16
	VEOR3 s3.B16, s4.B16, tag.B16, tag.B16
	VEOR  s5.B16, tag.B16, tag.B16

	MOVD expectedTag+16(FP), dst_ptr
	VST1 [tag.B16], (dst_ptr)

	RET

#undef src_ptr
#undef dst_ptr
#undef remain
#undef key_ptr
#undef nonce_ptr
#undef ad_len
#undef ct_len
#undef stack_ptr

#undef k0
#undef k1
#undef n0
#undef n1
#undef kn0
#undef kn1
#undef C0
#undef C1
#undef z
#undef xi
#undef ci
#undef t
#undef v
#undef out
#undef tag
#undef fix

// func aesRound(out, in, rk *[16]byte)
TEXT ·aesRound(SB), NOSPLIT, $0-24
#define in_ptr R9
#define rk_ptr R10
#define out_ptr R11
#define block V30
#define key V31

	MOVD out+0(FP), out_ptr
	MOVD in+8(FP), in_ptr
	MOVD rk+16(FP), rk_ptr
	VLD1 (in_ptr), [block.B16]
	VLD1 (rk_ptr), [key.B16]
	INIT_ZERO()
	AES_ROUND(block, key)
	VST1 [block.B16], (out_ptr)
	RET

#undef in_ptr
#undef rk_ptr
#undef out_ptr
#undef block
#undef key
