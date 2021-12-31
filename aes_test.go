package aegis

import "testing"

// TestAESRound tests the AESRound routine.
//
// See [aegis] A.1.
func TestAESRound(t *testing.T) {
	for _, tc := range []struct {
		in  uint128
		rk  uint128
		out uint128
	}{
		{
			in:  uint128{0x0001020304050607, 0x08090a0b0c0d0e0f},
			rk:  uint128{0x1011121314151617, 0x18191a1b1c1d1e1f},
			out: uint128{0x7a7b4e5638782546, 0xa8c0477a3b813f43},
		},
	} {
		out := aesRound(tc.in, tc.rk)
		if out != tc.out {
			t.Fatalf("expected (%#0.16x, %#0.16x), got (%#0.16x, %#0.16x)",
				tc.out.hi, tc.out.hi, out.hi, out.lo)
		}
	}
}
