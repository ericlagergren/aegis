package main

import (
	"fmt"
	"math/rand"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/gotypes"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run asm.go -out ../aegis_amd64.s -stubs ../stub_amd64.go -pkg aegis

var (
	rev64mask Mem
	C0        Mem
	C1        Mem
)

func main() {
	Package("github.com/ericlagergren/aegis")
	ConstraintExpr("gc,!purego")

	rev64mask = GLOBL("rev64mask", RODATA|NOPTR)
	DATA(0, U64(0x0001020304050607))
	DATA(8, U64(0x08090a0b0c0d0e0f))

	C0 = GLOBL("C0", RODATA|NOPTR)
	DATA(0, U64(0x0d08050302010100))
	DATA(8, U64(0x6279e99059372215))

	C1 = GLOBL("C1", RODATA|NOPTR)
	DATA(0, U64(0xf12fc26d55183ddb))
	DATA(8, U64(0xdd28b57342311120))

	declareAESRound()
	declareSeal128L()
	declareOpen128L()
	declareUpdate128L()
	declareSeal256()
	declareOpen256()
	declareUpdate256()

	Generate()
}

func declareAESRound() {
	TEXT("aesRoundAsm", NOSPLIT, "func(out, in, rk *[16]byte)")
	Pragma("noescape")

	inp := Mem{Base: Load(Param("in"), GP64())}
	rkp := Mem{Base: Load(Param("rk"), GP64())}
	outp := Mem{Base: Load(Param("out"), GP64())}

	out, rk := XMM(), XMM()
	MOVOU(inp, out)
	MOVOU(rkp, rk)
	AESENC(rk, out)
	MOVOU(out, outp)

	RET()
}

type state128l [8]VecVirtual

func (s *state128l) clear() {
	for i := range s {
		PXOR(s[i], s[i])
	}
}

func (s *state128l) init(key, nonce Mem) {
	for i := range s {
		s[i] = XMM()
	}

	k, n := XMM(), XMM()
	MOVOU(key, k)
	MOVOU(nonce, n)

	Comment("S0 = key ^ nonce")
	MOVOU(k, s[0])
	PXOR(n, s[0])

	Comment("S1 = C1")
	MOVOU(C1, s[1])

	Comment("S2 = C0")
	MOVOU(C0, s[2])

	Comment("S3 = C1")
	MOVOU(C1, s[3])

	Comment("S4 = key ^ nonce")
	MOVOU(s[0], s[4])

	Comment("S5 = key ^ C0")
	MOVOU(key, s[5])
	PXOR(C0, s[5])

	Comment("S6 = key ^ C1")
	MOVOU(key, s[6])
	PXOR(C1, s[6])

	Comment("S7 = key ^ C0")
	MOVOU(s[5], s[7])

	Comment("Repeat(10, Update(nonce, key))")
	for i := 0; i < 10; i++ {
		s.update(n, k)
	}
}

func (s *state128l) update(m0, m1 VecVirtual) {
	tmp0 := XMM()
	MOVOU(s[7], tmp0)
	for i := 7; i > 0; i-- {
		Commentf("S[%d] = AESRound(S[%d], S[%d])", i, i-1, i)
		tmp := XMM()
		MOVOU(s[i-1], tmp)
		AESENC(s[i], tmp)
		MOVOU(tmp, s[i])
	}
	Comment("S[0] = AESRound(tmp, S[0])")
	AESENC(s[0], tmp0)
	MOVOU(tmp0, s[0])

	Comment("S[0] ^= M0")
	PXOR(m0, s[0])

	Comment("S[4] ^= M1")
	PXOR(m1, s[4])
}

func (s *state128l) finalize(adLen, mdLen Op) VecVirtual {
	Comment("t = S2 ^ (LE64(ad_len) || LE64(msg_len))")
	SHLQ(U8(3), adLen)
	SHLQ(U8(3), mdLen)
	// Since we have two fixed-size integers we can insert them
	// into t instead of writing them to the stack and reading
	// them back into t.
	t := XMM()
	MOVQ(adLen, t)          // low
	PINSRQ(U8(1), mdLen, t) // high
	PXOR(s[2], t)

	// Repeat(7, Update(t, t))
	for i := 0; i < 7; i++ {
		s.update(t, t)
	}

	Comment("tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6")
	tag := XMM()
	MOVOU(s[0], tag)
	for i := 1; i <= 6; i++ {
		PXOR(s[i], tag)
	}
	return tag
}

func declareUpdate128L() {
	TEXT("update128LAsm", NOSPLIT, "func(s *state128L, m *[BlockSize128L]byte)")
	Pragma("noescape")

	sp := Mem{Base: Load(Param("s"), GP64())}
	mp := Mem{Base: Load(Param("m"), GP64())}

	mask := XMM()
	MOVOU(rev64mask, mask)

	Comment("Load state")
	var s state128l
	for i := range s {
		s[i] = XMM()
		MOVOU(sp.Offset(i*16), s[i])
		PSHUFB(mask, s[i])
	}

	m0, m1 := XMM(), XMM()
	MOVOU(mp, m0)
	MOVOU(mp.Offset(16), m1)
	s.update(m0, m1)

	Comment("Store state")
	for i := range s {
		PSHUFB(mask, s[i])
		MOVOU(s[i], sp.Offset(i*16))
	}
	RET()
}

func declareSeal128L() {
	TEXT("seal128LAsm", NOSPLIT, "func(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, plaintext, additionalData []byte)")
	Pragma("noescape")

	stack := AllocLocal(32)
	dst := Mem{Base: Load(Param("out").Base(), GP64())}
	ctr := GP64()

	var s state128l
	s.init(
		Mem{Base: Load(Param("key"), GP64())},
		Mem{Base: Load(Param("nonce"), GP64())},
	)

	// ad_blocks = Split(Pad(ad, 256), 256)
	// for xi in ad_blocks:
	//     Enc(xi)
	Label("auth")

	adSrc := Mem{Base: Load(Param("additionalData").Base(), GP64())}

	Comment(
		"ctr := len(additionalData) / 32",
		"if ctr == 0 { goto authPartial }",
	)
	Load(Param("additionalData").Len(), ctr)
	SHRQ(U8(5), ctr)
	JZ(LabelRef("authPartial"))

	// Full AD block(s).
	Label("authFull")
	ad0, ad1 := XMM(), XMM()
	MOVOU(adSrc, ad0)
	MOVOU(adSrc.Offset(16), ad1)
	s.update(ad0, ad1)
	Comment(
		"additionalData = additionalData[32:]",
		"ctr--",
		"if ctr != 0 { goto authFull }",
	)
	ADDQ(U8(32), adSrc.Base)
	SUBQ(U8(1), ctr)
	JNZ(LabelRef("authFull"))

	// Partial AD block.
	Label("authPartial")

	Comment(
		"adRemain := len(additionalData) % 32",
		"if adRemain == 0 { goto encrypt }",
	)
	adRemain := Load(Param("additionalData").Len(), GP64())
	ANDQ(U8(31), adRemain)
	JZ(LabelRef("encrypt"))

	clear32(stack)
	copyN(stack, adSrc, adRemain)
	m0, m1 := XMM(), XMM()
	MOVOU(stack, m0)
	MOVOU(stack.Offset(16), m1)
	s.update(m0, m1)

	// msg_blocks = Split(Pad(msg, 256), 256)
	// for xi in msg_blocks:
	//     ct = ct || Enc(xi)
	Label("encrypt")

	ptSrc := Mem{Base: Load(Param("plaintext").Base(), GP64())}
	Comment(
		"ctr := len(plaintext) / 32",
		"if ctr == 0 { goto encryptPartial }",
	)
	Load(Param("plaintext").Len(), ctr)
	SHRQ(U8(5), ctr)
	JZ(LabelRef("encryptPartial"))

	Label("encryptFull")
	Comment("z0 = S6 ^ S1 ^ (S2 & S3)")
	z0 := XMM()
	MOVOU(s[3], z0)
	PAND(s[2], z0)
	PXOR(s[1], z0)
	PXOR(s[6], z0)

	Comment("z1 = S2 ^ S5 ^ (S6 & S7)")
	z1 := XMM()
	MOVOU(s[7], z1)
	PAND(s[6], z1)
	PXOR(s[5], z1)
	PXOR(s[2], z1)

	// t0, t1 = Split(xi, 128)
	t0, t1 := XMM(), XMM()
	MOVOU(ptSrc, t0)
	MOVOU(ptSrc.Offset(16), t1)

	Comment("outN = tN ^ zN")
	out0 := z0
	PXOR(t0, out0)
	out1 := z1
	PXOR(t1, out1)

	Comment("Update(t0, t1)")
	s.update(t0, t1)

	Comment("ci = out0 || out1")
	MOVOU(out0, dst)
	MOVOU(out1, dst.Offset(16))

	Comment(
		"ciphertext = ciphertext[32:]",
		"plaintext = plaintext[32:]",
		"ctr--",
		"if ctr != 0 { goto encryptFull }",
	)
	ADDQ(U8(32), dst.Base)
	ADDQ(U8(32), ptSrc.Base)
	SUBQ(U8(1), ctr)
	JNZ(LabelRef("encryptFull"))

	Label("encryptPartial")
	Comment(
		"ptRemain := len(plaintext) % 32",
		"if ptRemain == 0 { goto finalize }",
	)
	ptRemain := Load(Param("plaintext").Len(), GP64())
	ANDQ(U8(31), ptRemain)
	JZ(LabelRef("finalize"))

	Comment("z0 = S6 ^ S1 ^ (S2 & S3)")
	MOVOU(s[3], z0)
	PAND(s[2], z0)
	PXOR(s[1], z0)
	PXOR(s[6], z0)

	Comment("z1 = S2 ^ S5 ^ (S6 & S7)")
	MOVOU(s[7], z1)
	PAND(s[6], z1)
	PXOR(s[5], z1)
	PXOR(s[2], z1)

	// t0, t1 = Split(xi, 128)
	Comment(
		"Clear 32 bytes on the stack, copy over the remaining",
		"plaintext, then read back t0 and t1 from the stack.",
	)
	clear32(stack)
	copyN(stack, ptSrc, ptRemain)
	MOVOU(stack, t0)
	MOVOU(stack.Offset(16), t1)

	Comment("outN = tN ^ zN")
	out0 = z0
	PXOR(t0, out0)
	out1 = z1
	PXOR(t1, out1)

	Comment("Update(t0, t1)")
	s.update(t0, t1)

	Comment("ci = out0 || out1")
	MOVOU(out0, stack)
	MOVOU(out1, stack.Offset(16))
	copyN(dst, stack, ptRemain)
	ADDQ(ptRemain, dst.Base)

	Label("finalize")
	tag := s.finalize(
		Load(Param("additionalData").Len(), GP64()),
		Load(Param("plaintext").Len(), GP64()),
	)
	MOVOU(tag, dst)

	s.clear()
	RET()
}

func declareOpen128L() {
	TEXT("open128LAsm", NOSPLIT, "func(key *[KeySize128L]byte, nonce *[NonceSize128L]byte, out, ciphertext, tag, additionalData []byte) (ok bool)")
	Pragma("noescape")

	stack := AllocLocal(32)
	dst := Mem{Base: Load(Param("out").Base(), GP64())}
	ctr := GP64()

	var s state128l
	s.init(
		Mem{Base: Load(Param("key"), GP64())},
		Mem{Base: Load(Param("nonce"), GP64())},
	)

	// ad_blocks = Split(Pad(ad, 256), 256)
	// for xi in ad_blocks:
	//     Enc(xi)
	Label("auth")

	adSrc := Mem{Base: Load(Param("additionalData").Base(), GP64())}

	Comment(
		"ctr := len(additionalData) / 32",
		"if ctr == 0 { goto authPartial }",
	)
	Load(Param("additionalData").Len(), ctr)
	SHRQ(U8(5), ctr)
	JZ(LabelRef("authPartial"))

	// Full AD block(s).
	Label("authFull")
	ad0, ad1 := XMM(), XMM()
	MOVOU(adSrc, ad0)
	MOVOU(adSrc.Offset(16), ad1)
	s.update(ad0, ad1)
	Comment(
		"additionalData = additionalData[32:]",
		"ctr--",
		"if ctr != 0 { goto authFull }",
	)
	ADDQ(U8(32), adSrc.Base)
	SUBQ(U8(1), ctr)
	JNZ(LabelRef("authFull"))

	// Partial AD block.
	Label("authPartial")

	Comment(
		"adRemain := len(additionalData) % 32",
		"if adRemain == 0 { goto decrypt }",
	)
	adRemain := Load(Param("additionalData").Len(), GP64())
	ANDQ(U8(31), adRemain)
	JZ(LabelRef("decrypt"))

	clear32(stack)
	copyN(stack, adSrc, adRemain)
	MOVOU(stack, ad0)
	MOVOU(stack.Offset(16), ad1)
	s.update(ad0, ad1)

	// ct_blocks = Split(ct, 256)
	// cn = Tail(ct, |ct| mod 256)
	//
	// for ci in ct_blocks:
	//     msg = msg || Dec(ci)
	// if cn is not empty:
	//     msg = msg || DecPartial(cn)
	Label("decrypt")

	ctSrc := Mem{Base: Load(Param("ciphertext").Base(), GP64())}
	Comment(
		"ctr := len(ciphertext) / 32",
		"if ctr == 0 { goto decryptPartial }",
	)
	Load(Param("ciphertext").Len(), ctr)
	SHRQ(U8(5), ctr)
	JZ(LabelRef("decryptPartial"))

	Label("decryptFull")
	Comment("z0 = S6 ^ S1 ^ (S2 & S3)")
	z0 := XMM()
	MOVOU(s[3], z0)
	PAND(s[2], z0)
	PXOR(s[1], z0)
	PXOR(s[6], z0)

	Comment("z1 = S2 ^ S5 ^ (S6 & S7)")
	z1 := XMM()
	MOVOU(s[7], z1)
	PAND(s[6], z1)
	PXOR(s[5], z1)
	PXOR(s[2], z1)

	// t0, t1 = Split(ci, 128)
	t0, t1 := XMM(), XMM()
	MOVOU(ctSrc, t0)
	MOVOU(ctSrc.Offset(16), t1)

	Comment("outN = tN ^ zN")
	out0 := z0
	PXOR(t0, out0)
	out1 := z1
	PXOR(t1, out1)

	Comment("Update(out0, out1)")
	s.update(out0, out1)

	Comment("xi = out0 || out1")
	MOVOU(out0, dst)
	MOVOU(out1, dst.Offset(16))

	Comment(
		"plaintext = plaintext[32]",
		"ciphertext = ciphertext[32:]",
		"ctr--",
		"if ctr != 0 { goto decryptFull }",
	)
	ADDQ(U8(32), dst.Base)
	ADDQ(U8(32), ctSrc.Base)
	SUBQ(U8(1), ctr)
	JNZ(LabelRef("decryptFull"))

	Label("decryptPartial")
	Comment(
		"ctRemain := len(ciphertext) % 32",
		"if ctRemain == 0 { goto finalize }",
	)
	ctRemain := Load(Param("ciphertext").Len(), GP64())
	ANDQ(U8(31), ctRemain)
	JZ(LabelRef("finalize"))

	Comment("z0 = S6 ^ S1 ^ (S2 & S3)")
	MOVOU(s[3], z0)
	PAND(s[2], z0)
	PXOR(s[1], z0)
	PXOR(s[6], z0)

	Comment("z1 = S2 ^ S5 ^ (S6 & S7)")
	MOVOU(s[7], z1)
	PAND(s[6], z1)
	PXOR(s[5], z1)
	PXOR(s[2], z1)

	// t0, t1 = Split(Pad(cn, 256), 128)
	Comment(
		"Clear 32 bytes on the stack, copy over the remaining",
		"ciphertext, then read back t0 and t1 from the stack.",
	)
	clear32(stack)
	copyN(stack, ctSrc, ctRemain)
	MOVOU(stack, t0)
	MOVOU(stack.Offset(16), t1)

	Comment("outN = tN ^ zN")
	out0 = z0
	PXOR(t0, out0)
	out1 = z1
	PXOR(t1, out1)

	Comment("xn = Truncate(out0 || out1, |cn|)")
	MOVOU(out0, stack)
	MOVOU(out1, stack.Offset(16))
	copyN(dst, stack, ctRemain)

	Comment("v0, v1 = Split(Pad(xn, 256), 128)")
	v0 := XMM()
	MOVOU(stack, v0)
	v1 := XMM()
	MOVOU(stack.Offset(16), v1)

	Comment("Update(v0, v1)")
	s.update(v0, v1)

	Comment(
		"Fix s0 and s4 which were incorrectly calculated because",
		"bytes 32-|cn| in |stack_ptr| weren't cleared before",
		"loading (v0, v1). Alternatively, we could clear those",
		"bits, but this results in simpler code.",
	)
	clearN(stack, ctRemain)
	MOVOU(stack, v0)
	PXOR(v0, s[0])
	MOVOU(stack.Offset(16), v0)
	PXOR(v0, s[4])

	Label("finalize")
	expectedTag := s.finalize(
		Load(Param("additionalData").Len(), GP64()),
		Load(Param("ciphertext").Len(), GP64()),
	)

	Comment("Constant time tag comparison")
	tag := XMM()
	MOVOU(Mem{Base: Load(Param("tag").Base(), GP64())}, tag)
	ok := mustResolve(Return("ok"))
	constantTimeCompare(ok.Addr, tag, expectedTag)

	Label("done")
	clear32(stack)
	s.clear()
	PXOR(out0, out0)
	PXOR(out1, out1)
	RET()
}

type state256 [6]VecVirtual

func (s *state256) clear() {
	for i := range s {
		PXOR(s[i], s[i])
	}
}

func (s *state256) init(key, nonce Mem) {
	for i := range s {
		s[i] = XMM()
	}

	k0, k1 := XMM(), XMM()
	MOVOU(key, k0)
	MOVOU(key.Offset(16), k1)
	n0, n1 := XMM(), XMM()
	MOVOU(nonce, n0)
	MOVOU(nonce.Offset(16), n1)

	Comment("S0 = k0 ^ n0")
	MOVOU(k0, s[0])
	PXOR(n0, s[0])

	Comment("S1 = k1 ^ n1")
	MOVOU(k1, s[1])
	PXOR(n1, s[1])

	Comment("S2 = C1")
	MOVOU(C1, s[2])

	Comment("S3 = C0")
	MOVOU(C0, s[3])

	Comment("S4 = k0 ^ C0")
	MOVOU(k0, s[4])
	PXOR(C0, s[4])

	Comment("S5 = k1 ^ C1")
	MOVOU(k1, s[5])
	PXOR(C1, s[5])

	Comment(
		"Repeat(4,",
		" Update(k0)",
		" Update(k1)",
		" Update(k0 ^ n0)",
		" Update(k1 ^ n1)",
		")",
	)
	kn0, kn1 := XMM(), XMM()
	MOVOU(k0, kn0)
	PXOR(n0, kn0)
	MOVOU(k1, kn1)
	PXOR(n1, kn1)
	for i := 0; i < 4; i++ {
		s.update(k0)
		s.update(k1)
		s.update(kn0)
		s.update(kn1)
	}
}

func (s *state256) update(m VecVirtual) {
	tmp0 := XMM()
	MOVOU(s[5], tmp0)
	for i := 5; i > 0; i-- {
		Commentf("S[%d] = AESRound(S[%d], S[%d])", i, i-1, i)
		tmp := XMM()
		MOVOU(s[i-1], tmp)
		AESENC(s[i], tmp)
		MOVOU(tmp, s[i])
	}
	Comment("S[0] = AESRound(tmp, S[0])")
	AESENC(s[0], tmp0)
	MOVOU(tmp0, s[0])

	Comment("S[0] ^= M")
	PXOR(m, s[0])
}

func (s *state256) finalize(adLen, mdLen Op) VecVirtual {
	Comment("t = S3 ^ (LE64(ad_len) || LE64(msg_len))")
	SHLQ(U8(3), adLen)
	SHLQ(U8(3), mdLen)
	// Since we have two fixed-size integers we can insert them
	// into t instead of writing them to the stack and reading
	// them back into t.
	t := XMM()
	MOVQ(adLen, t)          // low
	PINSRQ(U8(1), mdLen, t) // high
	PXOR(s[3], t)

	// Repeat(7, Update(t))
	for i := 0; i < 7; i++ {
		s.update(t)
	}

	Comment("tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5")
	tag := XMM()
	MOVOU(s[0], tag)
	for i := 1; i <= 5; i++ {
		PXOR(s[i], tag)
	}
	return tag
}

func declareUpdate256() {
	TEXT("update256Asm", NOSPLIT, "func(s *state256, m *[BlockSize256]byte)")
	Pragma("noescape")

	sp := Mem{Base: Load(Param("s"), GP64())}
	mp := Mem{Base: Load(Param("m"), GP64())}

	mask := XMM()
	MOVOU(rev64mask, mask)

	Comment("Load state")
	var s state256
	for i := range s {
		s[i] = XMM()
		MOVOU(sp.Offset(i*16), s[i])
		PSHUFB(mask, s[i])
	}

	m := XMM()
	MOVOU(mp, m)
	s.update(m)

	Comment("Store state")
	for i := range s {
		PSHUFB(mask, s[i])
		MOVOU(s[i], sp.Offset(i*16))
	}
	s.clear()
	RET()
}

func declareSeal256() {
	TEXT("seal256Asm", NOSPLIT, "func(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, plaintext, additionalData []byte)")
	Pragma("noescape")

	stack := AllocLocal(16)
	dst := Mem{Base: Load(Param("out").Base(), GP64())}
	ctr := GP64()

	var s state256
	s.init(
		Mem{Base: Load(Param("key"), GP64())},
		Mem{Base: Load(Param("nonce"), GP64())},
	)

	// ad_blocks = Split(Pad(ad, 128), 128)
	// for xi in ad_blocks:
	//     Enc(xi)
	Label("auth")

	adSrc := Mem{Base: Load(Param("additionalData").Base(), GP64())}

	Comment(
		"ctr := len(additionalData) / 16",
		"if ctr == 0 { goto authPartial }",
	)
	Load(Param("additionalData").Len(), ctr)
	SHRQ(U8(4), ctr)
	JZ(LabelRef("authPartial"))

	// Full AD block(s).
	Label("authFull")
	ad := XMM()
	MOVOU(adSrc, ad)
	s.update(ad)
	Comment(
		"additionalData = additionalData[16:]",
		"ctr--",
		"if ctr != 0 { goto authFull }",
	)
	ADDQ(U8(16), adSrc.Base)
	SUBQ(U8(1), ctr)
	JNZ(LabelRef("authFull"))

	// Partial AD block.
	Label("authPartial")

	Comment(
		"adRemain := len(additionalData) % 16",
		"if adRemain == 0 { goto encrypt }",
	)
	adRemain := Load(Param("additionalData").Len(), GP64())
	ANDQ(U8(15), adRemain)
	JZ(LabelRef("encrypt"))

	clear16(stack)
	copyN(stack, adSrc, adRemain)
	MOVOU(stack, ad)
	s.update(ad)

	// msg_blocks = Split(Pad(msg, 128), 128)
	// for xi in msg_blocks:
	//     ct = ct || Enc(xi)
	Label("encrypt")

	ptSrc := Mem{Base: Load(Param("plaintext").Base(), GP64())}
	Comment(
		"ctr := len(plaintext) / 16",
		"if ctr == 0 { goto encryptPartial }",
	)
	Load(Param("plaintext").Len(), ctr)
	SHRQ(U8(4), ctr)
	JZ(LabelRef("encryptPartial"))

	Label("encryptFull")
	Comment("z = S1 ^ S4 ^ S5 ^ (S2 & S3)")
	z := XMM()
	MOVOU(s[3], z)
	PAND(s[2], z)
	PXOR(s[5], z)
	PXOR(s[4], z)
	PXOR(s[1], z)

	Comment("Update(xi)")
	xi := XMM()
	MOVOU(ptSrc, xi)
	s.update(xi)

	Comment("ci = xi ^ z")
	PXOR(xi, z)
	MOVOU(z, dst)

	Comment(
		"ciphertext = ciphertext[16:]",
		"plaintext = plaintext[16:]",
		"ctr--",
		"if ctr != 0 { goto encryptFull }",
	)
	ADDQ(U8(16), dst.Base)
	ADDQ(U8(16), ptSrc.Base)
	SUBQ(U8(1), ctr)
	JNZ(LabelRef("encryptFull"))

	Label("encryptPartial")
	Comment(
		"ptRemain := len(plaintext) % 16",
		"if ptRemain == 0 { goto finalize }",
	)
	ptRemain := Load(Param("plaintext").Len(), GP64())
	ANDQ(U8(15), ptRemain)
	JZ(LabelRef("finalize"))

	Comment("z = S1 ^ S4 ^ S5 ^ (S2 & S3)")
	MOVOU(s[3], z)
	PAND(s[2], z)
	PXOR(s[5], z)
	PXOR(s[4], z)
	PXOR(s[1], z)

	Comment(
		"Clear 16 bytes on the stack, copy over the remaining",
		"plaintext, then read back xi from the stack.",
	)
	clear16(stack)
	copyN(stack, ptSrc, ptRemain)

	Comment("Update(xi)")
	MOVOU(stack, xi)
	s.update(xi)

	Comment("ci = xi ^ z")
	PXOR(xi, z)
	MOVOU(z, stack)
	copyN(dst, stack, ptRemain)
	ADDQ(ptRemain, dst.Base)

	Label("finalize")
	tag := s.finalize(
		Load(Param("additionalData").Len(), GP64()),
		Load(Param("plaintext").Len(), GP64()),
	)
	MOVOU(tag, dst)

	s.clear()
	RET()
}

func declareOpen256() {
	TEXT("open256Asm", NOSPLIT, "func(key *[KeySize256]byte, nonce *[NonceSize256]byte, out, ciphertext, tag, additionalData []byte) (ok bool)")
	Pragma("noescape")

	stack := AllocLocal(16)
	dst := Mem{Base: Load(Param("out").Base(), GP64())}
	ctr := GP64()

	var s state256
	s.init(
		Mem{Base: Load(Param("key"), GP64())},
		Mem{Base: Load(Param("nonce"), GP64())},
	)

	// ad_blocks = Split(Pad(ad, 128), 128)
	// for xi in ad_blocks:
	//     Enc(xi)
	Label("auth")

	adSrc := Mem{Base: Load(Param("additionalData").Base(), GP64())}

	Comment(
		"ctr := len(additionalData) / 16",
		"if ctr == 0 { goto authPartial }",
	)
	Load(Param("additionalData").Len(), ctr)
	SHRQ(U8(4), ctr)
	JZ(LabelRef("authPartial"))

	// Full AD block(s).
	Label("authFull")
	ad := XMM()
	MOVOU(adSrc, ad)
	s.update(ad)
	Comment(
		"additionalData = additionalData[16:]",
		"ctr--",
		"if ctr != 0 { goto authFull }",
	)
	ADDQ(U8(16), adSrc.Base)
	SUBQ(U8(1), ctr)
	JNZ(LabelRef("authFull"))

	// Partial AD block.
	Label("authPartial")

	Comment(
		"adRemain := len(additionalData) % 16",
		"if adRemain == 0 { goto decrypt }",
	)
	adRemain := Load(Param("additionalData").Len(), GP64())
	ANDQ(U8(15), adRemain)
	JZ(LabelRef("decrypt"))

	clear16(stack)
	copyN(stack, adSrc, adRemain)
	MOVOU(stack, ad)
	s.update(ad)

	// ct_blocks = Split(ct, 128)
	// cn = Tail(ct, |ct| mod 128)
	//
	// for ci in ct_blocks:
	//     msg = msg || Dec(ci)
	// if cn is not empty:
	//     msg = msg || DecPartial(cn)
	Label("decrypt")

	ctSrc := Mem{Base: Load(Param("ciphertext").Base(), GP64())}
	Comment(
		"ctr := len(ciphertext) / 16",
		"if ctr == 0 { goto decryptPartial }",
	)
	Load(Param("ciphertext").Len(), ctr)
	SHRQ(U8(4), ctr)
	JZ(LabelRef("decryptPartial"))

	Label("decryptFull")
	Comment("z = S1 ^ S4 ^ S5 ^ (S2 & S3)")
	z := XMM()
	MOVOU(s[3], z)
	PAND(s[2], z)
	PXOR(s[5], z)
	PXOR(s[4], z)
	PXOR(s[1], z)

	Comment("xi = ci ^ z")
	ci := XMM()
	MOVOU(ctSrc, ci)
	xi := z
	PXOR(ci, xi)
	MOVOU(xi, dst)

	Comment("Update(xi)")
	s.update(xi)

	Comment(
		"plaintext = plaintext[16:]",
		"ciphertext = ciphertext[16:]",
		"ctr--",
		"if ctr != 0 { goto decryptFull }",
	)
	ADDQ(U8(16), dst.Base)
	ADDQ(U8(16), ctSrc.Base)
	SUBQ(U8(1), ctr)
	JNZ(LabelRef("decryptFull"))

	Label("decryptPartial")
	Comment(
		"ctRemain := len(ciphertext) % 16",
		"if ctRemain == 0 { goto finalize }",
	)
	ctRemain := Load(Param("ciphertext").Len(), GP64())
	ANDQ(U8(15), ctRemain)
	JZ(LabelRef("finalize"))

	Comment("z = S1 ^ S4 ^ S5 ^ (S2 & S3)")
	MOVOU(s[3], z)
	PAND(s[2], z)
	PXOR(s[5], z)
	PXOR(s[4], z)
	PXOR(s[1], z)

	// t = Pad(ci, 128)
	Comment(
		"Clear 16 bytes on the stack, copy over the remaining",
		"ciphertext, then read back t0 and t1 from the stack.",
	)
	clear16(stack)
	copyN(stack, ctSrc, ctRemain)
	t := XMM()
	MOVOU(stack, t)

	Comment("outN = tN ^ zN")
	out := z
	PXOR(t, out)

	Comment("xn = Truncate(out, |cn|)")
	MOVOU(out, stack)
	copyN(dst, stack, ctRemain)

	Comment("v = Pad(xn, 128)")
	Comment("Update(v)")
	v := XMM()
	MOVOU(stack, v)
	s.update(v)

	Comment(
		"Fix s0 which was incorrectly calculated because",
		"bytes 16-|cn| in |stack_ptr| weren't cleared before",
		"loading v. Alternatively, we could clear those",
		"bits, but this results in simpler code.",
	)
	clearN(stack, ctRemain)
	MOVOU(stack, v)
	PXOR(v, s[0])

	Label("finalize")
	expectedTag := s.finalize(
		Load(Param("additionalData").Len(), GP64()),
		Load(Param("ciphertext").Len(), GP64()),
	)

	Comment("Constant time tag comparison")
	tag := XMM()
	MOVOU(Mem{Base: Load(Param("tag").Base(), GP64())}, tag)
	ok := mustResolve(Return("ok"))
	constantTimeCompare(ok.Addr, tag, expectedTag)

	Label("done")
	clear16(stack)
	s.clear()
	PXOR(z, z)
	RET()
}

func constantTimeCompare(dst Mem, tag, expectedTag VecVirtual) {
	PCMPEQB(tag, expectedTag)
	cmp := GP32()
	PMOVMSKB(expectedTag, cmp)
	CMPL(cmp, U32(0xffff))
	ok, err := Return("ok").Resolve()
	if err != nil {
		panic(err)
	}
	SETEQ(ok.Addr)
}

func clear16(dst Mem) {
	tmp := XMM()
	PXOR(tmp, tmp)
	MOVOU(tmp, dst)
}

func clear32(dst Mem) {
	tmp := XMM()
	PXOR(tmp, tmp)
	MOVOU(tmp, dst)
	MOVOU(tmp, dst.Offset(16))
}

var labelRng = rand.Uint32()

func copyN(dst, src Mem, len Register) {
	labelRng++
	label := func(s string) {
		Label(fmt.Sprintf("%s__%x", s, labelRng))
	}
	labelRef := func(s string) LabelRef {
		return LabelRef(fmt.Sprintf("%s__%x", s, labelRng))
	}
	TESTQ(len, len)
	JEQ(labelRef("move_0"))
	CMPQ(len, U8(2))
	JBE(labelRef("move_1or2"))
	CMPQ(len, U8(4))
	JB(labelRef("move_3"))
	JBE(labelRef("move_4"))
	CMPQ(len, U8(8))
	JB(labelRef("move_5through7"))
	JBE(labelRef("move_8"))
	CMPQ(len, U8(16))
	JBE(labelRef("move_9through16"))

	Comment("move_17through32")
	{
		tmp0 := XMM()
		tmp1 := XMM()
		MOVOU(src, tmp0)
		MOVOU(Mem{
			Base:  src.Base,
			Disp:  -16,
			Index: len,
			Scale: 1,
		}, tmp1)
		MOVOU(tmp0, dst)
		MOVOU(tmp1, Mem{
			Base:  dst.Base,
			Disp:  -16,
			Index: len,
			Scale: 1,
		})
		JMP(labelRef("move_0"))
	}

	label("move_9through16")
	{
		tmp0 := GP64()
		tmp1 := GP64()
		MOVQ(src, tmp0)
		MOVQ(Mem{
			Base:  src.Base,
			Disp:  -8,
			Index: len,
			Scale: 1,
		}, tmp1)
		MOVQ(tmp0, dst)
		MOVQ(tmp1, Mem{
			Base:  dst.Base,
			Disp:  -8,
			Index: len,
			Scale: 1,
		})
		JMP(labelRef("move_0"))
	}

	label("move_8")
	{
		tmp := GP64()
		MOVQ(src, tmp)
		MOVQ(tmp, dst)
		JMP(labelRef("move_0"))
	}

	label("move_5through7")
	{
		tmp0 := GP32()
		tmp1 := GP32()
		MOVL(src, tmp0)
		MOVL(Mem{
			Base:  src.Base,
			Disp:  -4,
			Index: len,
			Scale: 1,
		}, tmp1)
		MOVL(tmp0, dst)
		MOVL(tmp1, Mem{
			Base:  dst.Base,
			Disp:  -4,
			Index: len,
			Scale: 1,
		})
		JMP(labelRef("move_0"))
	}

	label("move_4")
	{
		tmp := GP32()
		MOVL(src, tmp)
		MOVL(tmp, dst)
		JMP(labelRef("move_0"))
	}

	label("move_3")
	{
		tmp0 := GP16()
		tmp1 := GP8()
		MOVW(src, tmp0)
		MOVB(src.Offset(2), tmp1)
		MOVW(tmp0, dst)
		MOVB(tmp1, dst.Offset(2))
		JMP(labelRef("move_0"))
	}

	label("move_1or2")
	{
		tmp0 := GP8()
		tmp1 := GP8()
		MOVB(src, tmp0)
		MOVB(Mem{
			Base:  src.Base,
			Disp:  -1,
			Index: len,
			Scale: 1,
		}, tmp1)
		MOVB(tmp0, dst)
		MOVB(tmp1, Mem{
			Base:  dst.Base,
			Disp:  -1,
			Index: len,
			Scale: 1,
		})
	}

	label("move_0")
}

func clearN(dst Mem, len Register) {
	labelRng++
	label := func(s string) {
		Label(fmt.Sprintf("%s__%x", s, labelRng))
	}
	labelRef := func(s string) LabelRef {
		return LabelRef(fmt.Sprintf("%s__%x", s, labelRng))
	}
	TESTQ(len, len)
	JEQ(labelRef("clear_0"))
	CMPQ(len, U8(2))
	JBE(labelRef("clear_1or2"))
	CMPQ(len, U8(4))
	JB(labelRef("clear_3"))
	JBE(labelRef("clear_4"))
	CMPQ(len, U8(8))
	JB(labelRef("clear_5through7"))
	JBE(labelRef("clear_8"))
	CMPQ(len, U8(16))
	JBE(labelRef("clear_9through16"))

	Comment("clear_17through32")
	{
		ZR := XMM()
		PXOR(ZR, ZR)
		MOVOU(ZR, dst)
		MOVOU(ZR, Mem{
			Base:  dst.Base,
			Disp:  -16,
			Index: len,
			Scale: 1,
		})
		JMP(labelRef("clear_0"))
	}

	label("clear_9through16")
	{
		ZR := GP64()
		XORQ(ZR, ZR)
		MOVQ(ZR, dst)
		MOVQ(ZR, Mem{
			Base:  dst.Base,
			Disp:  -8,
			Index: len,
			Scale: 1,
		})
		JMP(labelRef("clear_0"))
	}

	label("clear_8")
	{
		ZR := GP64()
		XORQ(ZR, ZR)
		MOVQ(ZR, dst)
		JMP(labelRef("clear_0"))
	}

	label("clear_5through7")
	{
		ZR := GP32()
		XORL(ZR, ZR)
		MOVL(ZR, dst)
		MOVL(ZR, Mem{
			Base:  dst.Base,
			Disp:  -4,
			Index: len,
			Scale: 1,
		})
		JMP(labelRef("clear_0"))
	}

	label("clear_4")
	{
		ZR := GP32()
		XORL(ZR, ZR)
		MOVL(ZR, dst)
		JMP(labelRef("clear_0"))
	}

	label("clear_3")
	{
		ZR := GP16()
		XORW(ZR, ZR)
		MOVW(ZR, dst)
		MOVB(ZR.As8(), dst.Offset(2))
		JMP(labelRef("clear_0"))
	}

	label("clear_1or2")
	{
		ZR := GP8()
		XORB(ZR, ZR)
		MOVB(ZR, dst)
		MOVB(ZR, Mem{
			Base:  dst.Base,
			Disp:  -1,
			Index: len,
			Scale: 1,
		})
	}

	label("clear_0")
}

func mustResolve(c Component) *Basic {
	ok, err := c.Resolve()
	if err != nil {
		panic(err)
	}
	return ok
}
