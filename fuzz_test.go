package aegis_test

import (
	"bytes"
	"testing"

	"github.com/ericlagergren/aegis"
	"github.com/ericlagergren/aegis/internal/ref"
)

func FuzzRef128L(f *testing.F) {
	fuzzRef(f, aegis.KeySize128L, aegis.NonceSize128L)
}

func FuzzRef256(f *testing.F) {
	fuzzRef(f, aegis.KeySize256, aegis.NonceSize256)
}

func fuzzRef(f *testing.F, keySize, nonceSize int) {
	key := make([]byte, keySize)
	nonce := make([]byte, nonceSize)
	plaintext := make([]byte, 4096)
	copy(plaintext, "hello, world.")
	f.Add(key, nonce, plaintext)
	f.Fuzz(func(t *testing.T, key, nonce, plaintext []byte) {
		if len(nonce) != nonceSize || len(key) != keySize {
			return
		}
		refAead, err := ref.New(key)
		if err != nil {
			t.Fatal(err)
		}
		gotAead, err := aegis.New(key)
		if err != nil {
			t.Fatal(err)
		}

		wantCt := refAead.Seal(nil, nonce, plaintext, nil)
		gotCt := gotAead.Seal(nil, nonce, plaintext, nil)
		if !bytes.Equal(wantCt, gotCt) {
			for i, c := range gotCt {
				if c != wantCt[i] {
					t.Fatalf("bad value at index %d of %d (%d): %#x",
						i, len(wantCt), len(wantCt)-i, c)
				}
			}
			t.Fatalf("expected %#x, got %#x", wantCt, gotCt)
		}
		wantPt, err := refAead.Open(nil, nonce, wantCt, nil)
		if err != nil {
			t.Fatal(err)
		}
		gotPt, err := gotAead.Open(nil, nonce, wantCt, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wantPt, gotPt) {
			t.Fatalf("expected %#x, got %#x", wantPt, gotPt)
		}
	})
}
