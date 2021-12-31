package aegis

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func unhex(s string) []byte {
	p, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return p
}

// TestUpdate128L tests AESIS-128L's Update routine.
//
// See [aegis] A.2.1.
func TestUpdate128L(t *testing.T) {
	for _, tc := range []struct {
		before [8]uint128
		m      [2]uint128
		after  [8]uint128
	}{
		{
			before: [8]uint128{
				{0x9b7e60b24cc873ea, 0x894ecc07911049a3},
				{0x330be08f35300faa, 0x2ebf9a7b0d274658},
				{0x7bbd5bd2b049f7b9, 0xb515cf26fbe7756c},
				{0xc35a00f55ea86c38, 0x86ec5e928f87db18},
				{0x9ebccafce87cab44, 0x6396c4334592c91f},
				{0x58d83e31f256371e, 0x60fc6bb257114601},
				{0x1639b56ea322c885, 0x68a176585bc915de},
				{0x640818ffb57dc0fb, 0xc2e72ae93457e39a},
			},
			m: [2]uint128{
				{0x033e6975b9481687, 0x9e42917650955aa0},
				{0x033e6975b9481687, 0x9e42917650955aa0},
			},
			after: [8]uint128{
				{0x596ab773e4433ca0, 0x127c73f60536769d},
				{0x790394041a3d26ab, 0x697bde865014652d},
				{0x38cf49e4b65248ac, 0xd533041b64dd0611},
				{0x16d8e58748f437bf, 0xff1797f780337cee},
				{0x69761320f7dd738b, 0x281cc9f335ac2f5a},
				{0xa21746bb193a569e, 0x331e1aa985d0d729},
				{0x09d714e6fcf9177a, 0x8ed1cde7e3d259a6},
				{0x61279ba73167f0ab, 0x76f0a11bf203bdff},
			},
		},
	} {
		s := tc.before
		update128L(&s, tc.m[0], tc.m[1])
		if s != tc.after {
			t.Fatalf("expected %#x, got %#x", tc.after, s)
		}
	}
}

// TestVectors128L tests AEGIS-128L's Encrypt routine.
//
// See [aegis] A.2 and https://github.com/jedisct1/rust-aegis/blob/e8f8bba41df8d0e95e8d896f055c472e6d63a162/src/lib.rs#L366
func TestVectors128L(t *testing.T) {
	for _, tc := range []struct {
		name           string
		key            []byte
		nonce          []byte
		additionalData []byte
		plaintext      []byte
		ciphertext     []byte // ciphertext || tag
	}{
		{
			name:       "A.2.2",
			key:        unhex("00000000000000000000000000000000"),
			nonce:      unhex("00000000000000000000000000000000"),
			plaintext:  unhex("00000000000000000000000000000000"),
			ciphertext: unhex("41de9000a7b5e40e2d68bb64d99ebb19f4d997cc9b94227ada4fe4165422b1c8"),
		},
		{
			name:       "A.2.3",
			key:        unhex("00000000000000000000000000000000"),
			nonce:      unhex("00000000000000000000000000000000"),
			ciphertext: unhex("83cc600dc4e3e7e62d4055826174f149"),
		},
		{
			name:           "A.2.4",
			key:            unhex("10010000000000000000000000000000"),
			nonce:          unhex("10000200000000000000000000000000"),
			additionalData: unhex("0001020304050607"),
			plaintext:      unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			ciphertext:     unhex("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84cc6f3372f6aa1bb82388d695c3962d9a"),
		},
		{
			name:           "A.2.5",
			key:            unhex("10010000000000000000000000000000"),
			nonce:          unhex("10000200000000000000000000000000"),
			additionalData: unhex("0001020304050607"),
			plaintext:      unhex("000102030405060708090a0b0c0d"),
			ciphertext:     unhex("79d94593d8c2119d7e8fd9b8fc775c04b3dba849b2701effbe32c7f0fab7"),
		},
		{
			name:           "jedisct1/rust-aegis",
			key:            []byte("YELLOW SUBMARINE"),
			nonce:          make([]byte, 16),
			additionalData: []byte("Comment numero un"),
			plaintext:      []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
			ciphertext: []byte{
				// Ciphertext
				137, 147, 98, 134, 30, 108, 100, 90, 185, 139, 110, 255, 169,
				201, 98, 232, 138, 159, 166, 71, 169, 80, 96, 205, 2, 109, 22,
				101, 71, 138, 231, 79, 130, 148, 159, 175, 131, 148, 166, 200,
				180, 159, 139, 138, 80, 104, 188, 50, 89, 53, 204, 111, 12,
				212, 196, 143, 98, 25, 129, 118, 132, 115, 95, 13, 232, 167,
				13, 59, 19, 143, 58, 59, 42, 206, 238, 139, 2, 251, 194, 222,
				185, 59, 143, 116, 231, 175, 233, 67, 229, 11, 219, 127, 160,
				215, 89, 217, 109, 89, 76, 225, 102, 118, 69, 94, 252, 2, 69,
				205, 251, 65, 159, 177, 3, 101,
				// Tag
				16, 244, 133, 167, 76, 40, 56, 136, 6, 235, 61, 139, 252, 7,
				57, 150,
			},
		},
	} {
		aead, err := New(tc.key)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := aead.Seal(nil, tc.nonce, tc.plaintext, tc.additionalData)
		if !bytes.Equal(ciphertext, tc.ciphertext) {
			t.Fatalf("%s: expected %#x, got %#x", tc.name, tc.ciphertext, ciphertext)
		}
		plaintext, err := aead.Open(nil, tc.nonce, tc.ciphertext, tc.additionalData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plaintext, tc.plaintext) {
			t.Fatalf("%s: expected %#x, got %#x", tc.name, tc.plaintext, plaintext)
		}
	}
}

type config struct {
	keySize   int
	nonceSize int
	blockSize int
}

var cfg128L = config{
	keySize:   KeySize128L,
	nonceSize: NonceSize128L,
	blockSize: BlockSize128L,
}

// TestRoundTrip tests encrypting and decrypting data.
func TestRoundTrip(t *testing.T) {
	t.Run("AEGIS-128L", func(t *testing.T) {
		testRoundTrip(t, cfg128L)
	})
}

func testRoundTrip(t *testing.T, cfg config) {
	key := make([]byte, cfg.keySize)
	nonce := make([]byte, cfg.nonceSize)
	plaintext := make([]byte, cfg.blockSize*50)
	if _, err := rand.Read(plaintext); err != nil {
		panic(err)
	}
	additionalData := make([]byte, len(plaintext))
	if _, err := rand.Read(additionalData); err != nil {
		panic(err)
	}
	for i := 0; i < len(plaintext); i++ {
		if _, err := rand.Read(key); err != nil {
			panic(err)
		}
		if _, err := rand.Read(nonce); err != nil {
			panic(err)
		}
		plaintext := plaintext[:i]
		additionalData := additionalData[:i]

		aead, err := New(key)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
		got, err := aead.Open(nil, nonce, ciphertext, additionalData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("expected %#x, got %#x", plaintext, got)
		}
	}
}

// TestInPlace tests in-place encryption and decryption.
func TestInPlace(t *testing.T) {
	t.Run("AEGIS-128L", func(t *testing.T) {
		testInPlace(t, cfg128L)
	})
}

func testInPlace(t *testing.T, cfg config) {
	key := make([]byte, cfg.keySize)
	nonce := make([]byte, cfg.nonceSize)
	plaintext := make([]byte, cfg.blockSize*50)
	additionalData := make([]byte, len(plaintext))
	if _, err := rand.Read(additionalData); err != nil {
		panic(err)
	}
	for i := 0; i < len(plaintext); i++ {
		if _, err := rand.Read(key); err != nil {
			panic(err)
		}
		if _, err := rand.Read(nonce); err != nil {
			panic(err)
		}
		plaintext := plaintext[:i]
		for i := range plaintext {
			plaintext[i] = byte(i)
		}
		additionalData := additionalData[:i]

		aead, err := New(key)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := aead.Seal(plaintext[:0], nonce, plaintext[:i], additionalData)
		got, err := aead.Open(ciphertext[:0], nonce, ciphertext, additionalData)
		if err != nil {
			t.Fatal(err)
		}
		for i, c := range got {
			if c != byte(i) {
				t.Fatalf("bad value at index %d: %#x", i, c)
			}
		}
	}
}

// TestNew tests the key sizes accepted by New.
func TestNew(t *testing.T) {
	for _, tc := range []struct {
		size int
		ok   bool
	}{
		{0, false},
		{15, false},
		{17, false},
		{31, false},
		{33, false},
		{KeySize128L, true},
	} {
		_, err := New(make([]byte, tc.size))
		if tc.ok != (err == nil) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}
