//go:build fuzz

package aegis_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/ericlagergren/aegis"
	"github.com/ericlagergren/aegis/internal/ref"
	rand "github.com/ericlagergren/saferand"
)

func TestFuzz(t *testing.T) {
	t.Run("AEGIS-128L", func(t *testing.T) {
		t.Parallel()

		testFuzz(t, aegis.KeySize128L, aegis.NonceSize128L)
	})
	t.Run("AEGIS-256", func(t *testing.T) {
		t.Parallel()

		testFuzz(t, aegis.KeySize256, aegis.NonceSize256)
	})
}

func testFuzz(t *testing.T, keySize, nonceSize int) {
	d := 2 * time.Second
	if testing.Short() {
		d = 10 * time.Millisecond
	}
	if s := os.Getenv("AEGIS_FUZZ_TIMEOUT"); s != "" {
		var err error
		d, err = time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := time.NewTimer(d)

	key := make([]byte, keySize)
	nonce := make([]byte, nonceSize)
	plaintext := make([]byte, 1*1024*1024) // 1 MB
	for i := 0; ; i++ {
		select {
		case <-tm.C:
			t.Logf("iters: %d", i)
			return
		default:
		}

		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		n := rand.Intn(len(plaintext))
		if _, err := rand.Read(plaintext[:n]); err != nil {
			t.Fatal(err)
		}
		plaintext := plaintext[:n]

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
	}
}
